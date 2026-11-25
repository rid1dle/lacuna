mod codes;
mod config;
mod dns;
mod rules;
mod store;

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::runtime::Builder;
use tracing::{error, info};
use tracing_subscriber::filter::LevelFilter;

use dns::pipeline::{self, LiveConfig, LogSink, Pipeline};
use dns::server::{self, Listeners};
use dns::upstream::{UdpUpstream, Upstream, Upstreams};
use store::{writer, Retention, Store};

const USAGE: &str = "usage: sieve <check-config <path> | serve <path> | \
                     ask <name> [type] [--server addr] [--expect ip]>";

/// `ask` waits this long for an answer, UDP plus a TCP retry.
const ASK_TIMEOUT: Duration = Duration::from_secs(2);
const ASK_SERVER: &str = "127.0.0.1:5353";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Matching on a slice of `&str` keeps the subcommand table readable without clap.
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["check-config", path] => match config::Config::load(Path::new(path)) {
            Ok(_) => {
                println!("ok");
                ExitCode::SUCCESS
            }
            Err(e) => {
                // `{:#}` prints the whole context chain on one line.
                println!("{e:#}");
                ExitCode::FAILURE
            }
        },
        ["serve", path] => serve(Path::new(path)),
        ["ask", rest @ ..] => match parse_ask(rest) {
            Ok(a) => ask(&a),
            Err(e) => {
                eprintln!("{e}\n{USAGE}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn serve(path: &Path) -> ExitCode {
    // Only a bare level is read from RUST_LOG: per-module filters need the env-filter
    // feature, which pulls in regex.
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::INFO);
    tracing_subscriber::fmt().with_max_level(level).init();

    let result = Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the tokio runtime")
        .and_then(|rt| rt.block_on(serve_dns(path)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn serve_dns(path: &Path) -> Result<()> {
    let config = config::Config::load(path)?;
    let mut store = Store::open(&config.store.path)?;
    store.retention = Retention {
        raw_days: config.store.raw_days,
        rollup_days: config.store.rollup_days,
    };
    info!(path = %config.store.path.display(), "query log open");
    let log: Arc<dyn LogSink> = Arc::new(writer::spawn(store, writer::CHANNEL_CAPACITY));

    // User rules only for now; filter lists join the set when the list manager lands.
    let (rules, stats) = rules::RuleSet::build(&config.user_rules, &[]);
    let skipped: usize = stats.iter().flat_map(|s| s.skipped.values()).sum();
    info!(rules = rules.rule_count(), skipped, "user rules loaded");

    let pipeline = Arc::new(Pipeline::new(
        pipeline::shared(rules),
        pipeline::shared(LiveConfig::from_config(&config)),
        Upstreams::from_config(&config.upstreams)?,
        config.dns.max_inflight,
    ));
    let listeners = Listeners::bind(config.dns.listen).await?;
    info!(addr = %listeners.local_addr()?, "dns listening on udp and tcp");
    tokio::select! {
        () = server::run(pipeline, listeners, log) => Ok(()),
        stop = shutdown_signal() => {
            info!("shutting down");
            stop
        }
    }
}

/// SIGTERM (docker stop) or ctrl-c. As PID 1 in a container the default signal
/// actions do nothing, so both must be handled.
async fn shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    tokio::select! {
        _ = term.recv() => Ok(()),
        r = tokio::signal::ctrl_c() => r.context("waiting for ctrl-c"),
    }
}

/// `ask <name> [type] [--server addr] [--expect ip]`
#[derive(Debug, PartialEq)]
struct Ask {
    name: Name,
    qtype: RecordType,
    server: SocketAddr,
    expect: Option<IpAddr>,
}

fn parse_ask(args: &[&str]) -> Result<Ask, String> {
    let mut positional = Vec::new();
    let mut server = ASK_SERVER;
    let mut expect = None;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--server" => server = it.next().ok_or("--server needs an address")?,
            "--expect" => expect = Some(*it.next().ok_or("--expect needs an ip")?),
            flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}")),
            word => positional.push(word),
        }
    }
    let (name, qtype) = match positional.as_slice() {
        [name] => (*name, "A"),
        [name, qtype] => (*name, *qtype),
        _ => return Err("ask takes a name and an optional type".into()),
    };
    // A trailing dot makes the name absolute, so nothing is appended to it.
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    Ok(Ask {
        name: Name::from_ascii(&fqdn).map_err(|e| format!("bad name {name}: {e}"))?,
        qtype: RecordType::from_str(&qtype.to_ascii_uppercase())
            .map_err(|_| format!("unknown type {qtype}"))?,
        server: server
            .parse()
            .map_err(|_| format!("bad server address {server}"))?,
        expect: expect
            .map(|ip| ip.parse().map_err(|_| format!("bad ip {ip}")))
            .transpose()?,
    })
}

/// One query: UDP, retried over TCP when truncated (the fallback upstream does exactly this).
async fn exchange(ask: &Ask) -> Result<Message> {
    let mut q = Message::new(0, MessageType::Query, OpCode::Query);
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(ask.name.clone(), ask.qtype));
    UdpUpstream::with_timeout(ask.server, ASK_TIMEOUT)
        .query(&q)
        .await
}

fn expect_met(expect: Option<IpAddr>, answer: &Message) -> bool {
    expect.is_none_or(|ip| pipeline::addresses(answer).contains(&ip))
}

/// Exit 1 on error or timeout, or when `--expect` is given and no A/AAAA answer is that
/// address; 0 otherwise. The container healthcheck relies on this.
fn ask(a: &Ask) -> ExitCode {
    let result = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the tokio runtime")
        .and_then(|rt| rt.block_on(exchange(a)));
    let answer = match result {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e:#}");
            return ExitCode::FAILURE;
        }
    };
    println!("{}", answer.metadata.response_code);
    for record in &answer.answers {
        println!("{record}");
    }
    if expect_met(a.expect, &answer) {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "no A/AAAA answer is {}",
            a.expect.map_or(String::new(), |ip| ip.to_string())
        );
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::pipeline::testing::{live, rules, upstreams, State};
    use crate::dns::pipeline::{shared, NoopSink};
    use hickory_proto::op::ResponseCode;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn ask_defaults_and_flags() {
        let a = parse_ask(&["example.com"]).unwrap();
        assert_eq!(a.name.to_ascii(), "example.com.");
        assert_eq!(a.qtype, RecordType::A);
        assert_eq!(a.server, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(a.expect, None);

        let a = parse_ask(&[
            "--server",
            "192.168.0.1:53",
            "x.lan.",
            "aaaa",
            "--expect",
            "::1",
        ])
        .unwrap();
        assert_eq!(a.name.to_ascii(), "x.lan.");
        assert_eq!(a.qtype, RecordType::AAAA);
        assert_eq!(a.server, "192.168.0.1:53".parse().unwrap());
        assert_eq!(a.expect, Some("::1".parse().unwrap()));
    }

    #[test]
    fn ask_rejects_bad_input() {
        for bad in [
            &[][..],
            &["a.com", "A", "extra"],
            &["a.com", "NOTATYPE"],
            &["a.com", "--server"],
            &["a.com", "--server", "nope"],
            &["a.com", "--expect", "nope"],
            &["a.com", "--bogus"],
        ] {
            assert!(parse_ask(bad).is_err(), "{bad:?}");
        }
    }

    /// Against a real server on loopback: the healthcheck path end to end.
    #[tokio::test]
    async fn ask_against_a_live_server() {
        let state = Arc::new(State::default());
        let p = Arc::new(Pipeline::new(
            rules(&[], ""),
            shared(live()),
            upstreams(&state, Duration::from_millis(1)),
            300,
        ));
        let listeners = Listeners::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listeners.local_addr().unwrap();
        tokio::spawn(server::run(p, listeners, Arc::new(NoopSink)));

        let server = addr.to_string();
        let ask = parse_ask(&["home.riddlelab.dev", "--server", &server]).unwrap();
        let m = exchange(&ask).await.unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert!(expect_met(Some("192.168.0.107".parse().unwrap()), &m));
        assert!(!expect_met(Some("192.168.0.108".parse().unwrap()), &m));
        assert!(expect_met(None, &m));

        // A big answer comes back truncated over UDP and is fetched again over TCP.
        let ask = parse_ask(&["big.example", "--server", &server]).unwrap();
        assert_eq!(exchange(&ask).await.unwrap().answers.len(), 40);
    }

    #[tokio::test]
    async fn ask_fails_when_nothing_answers() {
        // A bound socket that never replies: the 2s timeout must end the wait.
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = silent.local_addr().unwrap().to_string();
        let ask = parse_ask(&["example.com", "--server", &server]).unwrap();
        let started = std::time::Instant::now();
        assert!(exchange(&ask).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
