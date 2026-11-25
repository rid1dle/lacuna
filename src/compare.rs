//! `lacuna compare`: sends the same names to two DNS servers and reports where they
//! disagree. Used before cutover to hold lacuna against the live AdGuard.
//!
//! What matters is the outcome (blocked or allowed). Answer differences for allowed
//! names are reported too but are expected: CDNs rotate addresses between queries.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

use crate::dns::pipeline::addresses;
use crate::dns::upstream::{UdpUpstream, Upstream};

const TIMEOUT: Duration = Duration::from_secs(2);
const TYPES: [RecordType; 2] = [RecordType::A, RecordType::AAAA];

#[derive(Debug, Default, PartialEq)]
pub struct Totals {
    pub same: usize,
    pub differ_outcome: usize,
    pub differ_answers: usize,
    pub errors: usize,
}

/// One server's reply, reduced to what is compared.
struct Seen {
    blocked: bool,
    /// Sorted addresses, or the response code when there are none.
    answers: String,
}

impl Seen {
    fn of(m: &Message) -> Seen {
        let mut ips = addresses(m);
        ips.sort();
        // Blocking answers with the unspecified address (0.0.0.0 or ::).
        let blocked = ips.iter().any(IpAddr::is_unspecified);
        let answers = if ips.is_empty() {
            m.metadata.response_code.to_string()
        } else {
            ips.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(",")
        };
        Seen { blocked, answers }
    }

    fn outcome(&self) -> &'static str {
        if self.blocked {
            "blocked"
        } else {
            "allowed"
        }
    }
}

async fn ask(server: SocketAddr, name: &Name, qtype: RecordType) -> Result<Message> {
    let mut q = Message::new(0, MessageType::Query, OpCode::Query);
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(name.clone(), qtype));
    UdpUpstream::with_timeout(server, TIMEOUT).query(&q).await
}

/// Asks both servers for every name (A and AAAA), calls `report` with one line per
/// difference, and returns the totals. Names are asked one at a time, the two servers
/// together, so the live AdGuard is never hit with a burst.
pub async fn compare(
    a: SocketAddr,
    b: SocketAddr,
    names: &[String],
    mut report: impl FnMut(&str),
) -> Totals {
    let mut totals = Totals::default();
    for text in names {
        let Ok(name) = Name::from_ascii(format!("{text}.")) else {
            report(&format!("{text} - skipped: not a valid name"));
            totals.errors += TYPES.len();
            continue;
        };
        for qtype in TYPES {
            let (ra, rb) = tokio::join!(ask(a, &name, qtype), ask(b, &name, qtype));
            let (sa, sb) = match (ra, rb) {
                (Ok(ra), Ok(rb)) => (Seen::of(&ra), Seen::of(&rb)),
                (ra, rb) => {
                    let why = |r: Result<Message>| r.err().map_or("ok".into(), |e| format!("{e:#}"));
                    report(&format!("{text} {qtype} error a={} b={}", why(ra), why(rb)));
                    totals.errors += 1;
                    continue;
                }
            };
            if sa.blocked != sb.blocked {
                totals.differ_outcome += 1;
            } else if sa.answers != sb.answers {
                totals.differ_answers += 1;
            } else {
                totals.same += 1;
                continue;
            }
            report(&format!(
                "{text} {qtype} {} {} {} {}",
                sa.outcome(),
                sb.outcome(),
                sa.answers,
                sb.answers
            ));
        }
    }
    totals
}

/// One name per line; blank lines and `#` comments are skipped, names lowercased and
/// stripped of a trailing dot. `limit` keeps the first n.
pub fn parse_names(text: &str, limit: Option<usize>) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.trim_end_matches('.').to_ascii_lowercase())
        .take(limit.unwrap_or(usize::MAX))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::pipeline::shared;
    use crate::dns::pipeline::testing::{live, rules, upstreams, State};
    use crate::dns::pipeline::{NoopSink, Pipeline};
    use crate::dns::server::{self, Listeners};
    use std::sync::Arc;
    use std::time::Duration;

    /// A real server on loopback whose only difference is its user rules.
    async fn server_with(user: &[&str]) -> SocketAddr {
        let state = Arc::new(State::default());
        let p = Arc::new(Pipeline::new(
            rules(user, ""),
            shared(live()),
            upstreams(&state, Duration::from_millis(1)),
            300,
        ));
        let listeners = Listeners::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listeners.local_addr().unwrap();
        tokio::spawn(server::run(p, listeners, Arc::new(NoopSink)));
        addr
    }

    #[tokio::test]
    async fn compare_reports_outcome_difference() {
        let a = server_with(&["||ads.example^"]).await;
        let b = server_with(&[]).await;
        let names = ["ads.example", "fine.example"].map(String::from);
        let mut lines = Vec::new();
        let totals = compare(a, b, &names, |l| lines.push(l.to_string())).await;

        // ads.example is blocked on a only: A and AAAA both differ in outcome.
        // fine.example is allowed on both, and the fakes count calls, so its
        // answers differ without the outcome differing.
        assert_eq!(totals.differ_outcome, 2, "{lines:?}");
        assert_eq!(totals.errors, 0);
        let blocked: Vec<_> = lines
            .iter()
            .filter(|l| l.starts_with("ads.example "))
            .collect();
        assert_eq!(blocked.len(), 2, "{lines:?}");
        assert!(blocked[0].contains("blocked allowed"), "{}", blocked[0]);
        assert!(blocked[0].contains("0.0.0.0"), "{}", blocked[0]);
        assert_eq!(
            totals.same + totals.differ_outcome + totals.differ_answers + totals.errors,
            4
        );
    }

    #[tokio::test]
    async fn compare_counts_a_dead_server_as_errors() {
        let a = server_with(&[]).await;
        // Nothing listens on the discard port; the query times out or is refused.
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let names = ["x.example".to_string()];
        let totals = compare(a, dead, &names, |_| {}).await;
        assert_eq!(totals.errors, 2);
        assert_eq!(totals.same, 0);
    }

    #[test]
    fn names_file_skips_comments_and_honours_limit() {
        let text = "# header\n\nOne.Example\n two.example \nthree.example\n";
        assert_eq!(
            parse_names(text, None),
            ["one.example", "two.example", "three.example"]
        );
        assert_eq!(parse_names(text, Some(2)), ["one.example", "two.example"]);
    }
}
