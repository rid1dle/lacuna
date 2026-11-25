mod api;
mod clients;
mod codes;
mod compare;
mod config;
mod dns;
mod import;
mod lists;
mod rules;
mod store;

use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::runtime::Builder;
use tracing::{error, info, warn};
use tracing_subscriber::filter::LevelFilter;

use api::readonly::QueryLimits;
use dns::pipeline::{self, LiveConfig, LogSink, NoopSink, Pipeline};
use dns::server::{self, Listeners};
use dns::upstream::{Remote, UdpUpstream, Upstream, Upstreams};
use lists::{HttpFetcher, Lists};
use store::{writer, Retention, Store};

const USAGE: &str = "usage: lacuna <check-config <path> | serve <path> | \
                     ask <name> [type] [--server addr] [--expect ip] | \
                     import-adguard <file|-> [--db path] [--now-ms n] [--force] | \
                     compare --a addr --b addr --names file [--limit n]>";

/// `ask` waits this long for an answer, UDP plus a TCP retry.
const ASK_TIMEOUT: Duration = Duration::from_secs(2);
const ASK_SERVER: &str = "127.0.0.1:5353";
/// The database `import-adguard` writes to without `--db`: the deploy config's path.
const IMPORT_DB: &str = "/data/lacuna.db";
/// At shutdown: how long tokio tasks get to finish, then how long the log writer gets
/// to write what it holds. Both bounded so `docker stop` never hangs on them.
const TASKS_GRACE: Duration = Duration::from_secs(1);
const LOG_DRAIN: Duration = Duration::from_secs(3);

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
        ["import-adguard", rest @ ..] => match parse_import(rest) {
            Ok(i) => import_adguard(&i),
            Err(e) => {
                eprintln!("{e}\n{USAGE}");
                ExitCode::from(2)
            }
        },
        ["compare", rest @ ..] => match parse_compare(rest) {
            Ok(c) => run_compare(&c),
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

/// `compare --a addr --b addr --names file [--limit n]`
#[derive(Debug, PartialEq)]
struct Compare {
    a: SocketAddr,
    b: SocketAddr,
    names: PathBuf,
    limit: Option<usize>,
}

fn parse_compare(args: &[&str]) -> Result<Compare, String> {
    let (mut a, mut b, mut names, mut limit) = (None, None, None, None);
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        let mut value = |what: &str| it.next().copied().ok_or(format!("{arg} needs {what}"));
        match arg {
            "--a" => a = Some(value("an address")?),
            "--b" => b = Some(value("an address")?),
            "--names" => names = Some(value("a file")?),
            "--limit" => {
                let n = value("a number")?;
                limit = Some(n.parse().map_err(|_| format!("bad --limit {n}"))?);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let addr = |v: Option<&str>, flag: &str| -> Result<SocketAddr, String> {
        let v = v.ok_or(format!("compare needs {flag}"))?;
        v.parse().map_err(|_| format!("bad address {v}"))
    };
    Ok(Compare {
        a: addr(a, "--a")?,
        b: addr(b, "--b")?,
        names: PathBuf::from(names.ok_or("compare needs --names")?),
        limit,
    })
}

/// Prints one line per difference, then the totals. Exit 1 only when it cannot run
/// (unreadable names file); differences are the report, not a failure.
fn run_compare(c: &Compare) -> ExitCode {
    let text = match std::fs::read_to_string(&c.names) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("reading {}: {e}", c.names.display());
            return ExitCode::FAILURE;
        }
    };
    let names = compare::parse_names(&text, c.limit);
    let rt = match Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("starting the tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let t = rt.block_on(compare::compare(c.a, c.b, &names, |l| println!("{l}")));
    println!(
        "{{ same: {}, differ_outcome: {}, differ_answers: {}, errors: {} }}",
        t.same, t.differ_outcome, t.differ_answers, t.errors
    );
    ExitCode::SUCCESS
}

/// `import-adguard <file|-> [--db path] [--now-ms n] [--force]`. `-` reads stdin, so
/// the log can be piped out of AdGuard's container without a copy.
#[derive(Debug, PartialEq)]
struct Import {
    input: String,
    db: PathBuf,
    now_ms: Option<i64>,
    force: bool,
}

fn parse_import(args: &[&str]) -> Result<Import, String> {
    let mut input = None;
    let mut db = IMPORT_DB;
    let mut now_ms = None;
    let mut force = false;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--db" => db = it.next().ok_or("--db needs a path")?,
            "--now-ms" => {
                let n = it.next().ok_or("--now-ms needs a number")?;
                now_ms = Some(n.parse().map_err(|_| format!("bad --now-ms {n}"))?);
            }
            "--force" => force = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}")),
            word if input.is_none() => input = Some(word),
            _ => return Err("import-adguard takes one file".into()),
        }
    }
    Ok(Import {
        input: input
            .ok_or("import-adguard needs a file, or - for stdin")?
            .to_string(),
        db: PathBuf::from(db),
        now_ms,
        force,
    })
}

/// Prints the report on success; exit 1 on any error.
fn import_adguard(i: &Import) -> ExitCode {
    match run_import(i) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_import(i: &Import) -> Result<import::ImportReport> {
    let store = Store::open(&i.db)?;
    if i.force {
        store.forget_adguard_import()?;
    }
    let now = i.now_ms.unwrap_or_else(writer::now_ms);
    // The default retention is the deploy config's.
    let raw_days = store.retention.raw_days;
    if i.input == "-" {
        import::import_adguard(std::io::stdin().lock(), &store, now, raw_days)
    } else {
        let file = File::open(&i.input).with_context(|| format!("opening {}", i.input))?;
        import::import_adguard(BufReader::new(file), &store, now, raw_days)
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

    match serve_with_log(path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Starts the query log, serves DNS and the API until a shutdown signal, then lets the
/// log writer finish its last batch.
fn serve_with_log(path: &Path) -> Result<()> {
    let config = config::Config::load(path)?;
    ensure_sqlite_tmpdir();
    let opened = open_store(&config.store);
    // The API tells dashboards why there is no log, rather than showing empty panels.
    let store = opened.as_ref().map(|_| ()).map_err(|e| format!("{e:#}"));
    let (log, writer) = start_log(opened);
    let rt = Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the tokio runtime")?;
    let result = rt.block_on(serve_dns(&config, path, Arc::clone(&log), store));
    // Shutting the runtime down drops the tasks' clones of the sink; dropping ours
    // closes the channel, and the writer writes what it holds and exits.
    rt.shutdown_timeout(TASKS_GRACE);
    drop(log);
    if let Some(writer) = writer {
        if !writer.wait(LOG_DRAIN) {
            warn!("query log writer still busy after {LOG_DRAIN:?}, exiting anyway");
        }
    }
    result
}

/// SQLite spills big sorts to files (temp_store=FILE) in `SQLITE_TMPDIR`. In the
/// container the root is read-only, so compose points it at `/data/tmp`, which must exist.
/// Failing to create it is logged, not fatal: DNS does not need it.
fn ensure_sqlite_tmpdir() {
    if let Some(dir) = std::env::var_os("SQLITE_TMPDIR") {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            warn!("SQLITE_TMPDIR {}: {e}", Path::new(&dir).display());
        }
    }
}

fn open_store(c: &config::StoreConfig) -> Result<Store> {
    let mut store = Store::open(&c.path)?;
    store.retention = Retention {
        raw_days: c.raw_days,
        rollup_days: c.rollup_days,
    };
    info!(path = %c.path.display(), "query log open");
    Ok(store)
}

/// DNS never depends on the log: a store that fails to open (I/O, corruption, a newer
/// schema) is logged and DNS runs with a sink that drops every record.
fn start_log(opened: Result<Store>) -> (Arc<dyn LogSink>, Option<writer::WriterHandle>) {
    match opened {
        Ok(store) => {
            let (sender, handle) = writer::spawn(store, writer::CHANNEL_CAPACITY);
            (Arc::new(sender), Some(handle))
        }
        Err(e) => {
            error!("query log unavailable, serving DNS without it: {e:#}");
            (Arc::new(NoopSink), None)
        }
    }
}

async fn serve_dns(
    config: &config::Config,
    config_path: &Path,
    log: Arc<dyn LogSink>,
    store: Result<(), String>,
) -> Result<()> {
    // User rules first so DNS never starts with an empty set, then the last good lists
    // from disk (blocking is fine: nothing is listening yet).
    let (user_only, _) = rules::RuleSet::build(&config.user_rules, &[]);
    let rules = pipeline::shared(user_only);
    let upstreams = Arc::new(Upstreams::from_config(&config.upstreams)?);
    let lists = Arc::new(Lists::new(
        config.lists.clone(),
        config.user_rules.clone(),
        config.store.lists_dir.clone(),
        config.store.path.clone(),
        Arc::clone(&rules),
        HttpFetcher::new(Arc::clone(&upstreams)),
    ));
    lists.sync_meta().await;
    if let Err(e) = lists.load_last_good().await {
        error!("loading last good lists, serving user rules only: {e:#}");
    }

    let live = pipeline::shared(LiveConfig::from_config(config));
    let pipeline = Arc::new(Pipeline::new(
        Arc::clone(&rules),
        Arc::clone(&live),
        upstreams,
        config.dns.max_inflight,
    ));
    let listeners = Listeners::bind(config.dns.listen).await?;
    info!(addr = %listeners.local_addr()?, "dns listening on udp and tcp");
    tokio::spawn(refresh_loop(Arc::clone(&lists)));
    let api = Arc::new(api::ApiState::new(
        api::read_secret(&config.api.secret_file),
        store,
        QueryLimits {
            timeout: Duration::from_millis(config.api.query_timeout_ms),
            row_cap: config.api.row_cap,
        },
        config.api.max_concurrent,
        api::Runtime {
            config_path: config_path.to_path_buf(),
            db_path: config.store.path.clone(),
            pipeline: Arc::clone(&pipeline),
            lists,
            rules,
            live,
        },
    ));
    // DNS never depends on the API: a port that cannot be bound is logged, not fatal.
    match tokio::net::TcpListener::bind(config.api.listen).await {
        Ok(listener) => {
            info!(addr = %config.api.listen, "api listening");
            tokio::spawn(api::serve(listener, api));
        }
        Err(e) => error!(
            "api not started, serving DNS without it: {}: {e}",
            config.api.listen
        ),
    }
    // Names are resolved off the query path: config names now, router PTR in the background.
    if let Err(e) = clients::apply_config_names(&config.store.path, &config.devices) {
        warn!("device names from config not applied: {e:#}");
    }
    tokio::spawn(clients::Devices::new(config.store.path.clone(), config.dns.router).run());
    tokio::select! {
        () = server::run(pipeline, listeners, log) => Ok(()),
        stop = shutdown_signal() => {
            info!("shutting down");
            stop
        }
    }
}

/// First refresh shortly after start, then daily. A failed refresh is logged and the
/// next one tries again; the running rules are never touched by a failure.
async fn refresh_loop(lists: Arc<Lists<HttpFetcher<Remote>>>) {
    tokio::time::sleep(lists::FIRST_REFRESH).await;
    loop {
        let report = lists.refresh().await;
        info!("{}", report.summary());
        tokio::time::sleep(lists::next_refresh_in(&report)).await;
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
    use crate::dns::pipeline::shared;
    use crate::dns::pipeline::testing::{live, rules, upstreams, State};
    use crate::store::testing::TempDb;
    use hickory_proto::op::ResponseCode;
    use std::sync::Arc;
    use std::time::Duration;

    /// DNS never depends on the log: a store that cannot open leaves a no-op sink.
    #[test]
    fn log_failure_does_not_stop_dns() {
        let (_, writer) = start_log(Err(anyhow::anyhow!("disk gone")));
        assert!(writer.is_none());

        // A database from a newer lacuna is refused by the store; serve carries on.
        let db = TempDb::new("newer");
        Store::open(&db.0).unwrap();
        rusqlite::Connection::open(&db.0)
            .unwrap()
            .execute("UPDATE meta SET value = 2 WHERE key = 'schema_version'", [])
            .unwrap();
        let (_, writer) = start_log(Store::open(&db.0));
        assert!(writer.is_none());

        let (log, writer) = start_log(Store::open(Path::new(":memory:")));
        let writer = writer.expect("a store that opens gets a writer");
        drop(log);
        assert!(writer.wait(Duration::from_secs(3)));
    }

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

    #[test]
    fn compare_flags() {
        let c = parse_compare(&[
            "--a", "127.0.0.1:5300", "--b", "192.168.0.107:53", "--names", "n.txt", "--limit", "5",
        ])
        .unwrap();
        assert_eq!(c.b, "192.168.0.107:53".parse().unwrap());
        assert_eq!(c.limit, Some(5));
        for bad in [
            &[][..],
            &["--a", "1.2.3.4:53", "--b", "nope", "--names", "x"],
            &["--a", "1.2.3.4:53", "--b", "1.2.3.4:54"],
            &["--bogus"],
        ] {
            assert!(parse_compare(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sqlite_tmpdir_is_created() {
        let dir = std::env::temp_dir()
            .join(format!("lacuna-tmpdir-{}", std::process::id()))
            .join("tmp");
        // Only this test reads or writes SQLITE_TMPDIR.
        std::env::set_var("SQLITE_TMPDIR", &dir);
        ensure_sqlite_tmpdir();
        std::env::remove_var("SQLITE_TMPDIR");
        assert!(dir.is_dir());
        std::fs::remove_dir_all(dir.parent().unwrap()).ok();
    }

    #[test]
    fn import_defaults_and_flags() {
        assert_eq!(
            parse_import(&["-"]).unwrap(),
            Import {
                input: "-".into(),
                db: PathBuf::from(IMPORT_DB),
                now_ms: None,
                force: false,
            }
        );
        assert_eq!(
            parse_import(&["--force", "q.json", "--db", "/tmp/x.db", "--now-ms", "17"]).unwrap(),
            Import {
                input: "q.json".into(),
                db: PathBuf::from("/tmp/x.db"),
                now_ms: Some(17),
                force: true,
            }
        );
        for bad in [
            &[][..],
            &["a.json", "b.json"],
            &["a.json", "--db"],
            &["a.json", "--now-ms", "soon"],
            &["a.json", "--quiet"],
        ] {
            assert!(parse_import(bad).is_err(), "{bad:?}");
        }
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
