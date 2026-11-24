//! The query path: local answers, filtering, cache and upstream, in one fixed order.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::sync::Semaphore;
use tracing::warn;

use super::answer::{self, REWRITE_TTL};
use super::cache::{Cache, CacheKey, Lookup};
use super::upstream::{Remote, Upstream, UpstreamError, Upstreams};
use crate::codes::{Outcome, Reason, ServedFrom};
use crate::config::{Config, Rewrite};
use crate::rules::{RuleSet, Verdict};

/// Entries in the answer cache.
const CACHE_ENTRIES: usize = 20_000;

/// One handled query, as the log writer stores it.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are read by Task 8's writer; NoopSink drops them until then.
pub struct QueryRecord {
    pub ts_ms: i64,
    pub client: IpAddr,
    /// Lowercase, without the trailing dot.
    pub name: String,
    pub qtype: u16,
    pub rcode: u16,
    pub outcome: Outcome,
    pub reason: Reason,
    pub list_id: Option<u32>,
    pub rule: Option<Arc<str>>,
    pub served_from: ServedFrom,
    pub upstream: Option<String>,
    pub latency_us: u32,
    /// A and AAAA addresses in the response actually sent.
    pub answers: Vec<IpAddr>,
}

/// Where handled queries go. Task 8's writer implements it; `send` must never block.
pub trait LogSink: Send + Sync {
    fn send(&self, r: QueryRecord);
}

/// Drops every record (until the store exists).
pub struct NoopSink;

impl LogSink for NoopSink {
    fn send(&self, _: QueryRecord) {}
}

/// The parts of the config a reload may change while running.
#[derive(Debug, Clone)]
pub struct LiveConfig {
    pub rewrites: Vec<Rewrite>,
    pub refused_names: Vec<String>,
    pub blocked_ttl: u32,
}

impl LiveConfig {
    pub fn from_config(c: &Config) -> Self {
        LiveConfig {
            rewrites: c.rewrites.clone(),
            refused_names: c.dns.refused_names.clone(),
            blocked_ttl: c.dns.blocked_ttl,
        }
    }
}

/// Swappable shared state. Readers clone the inner `Arc` and drop the lock at once, so a
/// reload swapping in a new value never waits on a query in flight.
pub type Shared<T> = Arc<RwLock<Arc<T>>>;

pub fn shared<T>(value: T) -> Shared<T> {
    Arc::new(RwLock::new(Arc::new(value)))
}

fn current<T>(shared: &RwLock<Arc<T>>) -> Arc<T> {
    // A writer only ever replaces the whole `Arc`, so a poisoned lock still holds a whole value.
    Arc::clone(&shared.read().unwrap_or_else(PoisonError::into_inner))
}

/// Every mutex here guards a value replaced in one step, so poisoning cannot leave it torn.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The tokio clock as a std `Instant`: real time in production, the paused and manually
/// advanced clock in tests, so expiry and pauses are tested without sleeping.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Why the upstream path gave no answer.
enum FetchError {
    /// Every in-flight permit is taken.
    Busy,
    Failed(UpstreamError),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Busy => write!(f, "upstream in-flight cap reached"),
            FetchError::Failed(e) => e.fmt(f),
        }
    }
}

/// The upstream side. Background refreshes outlive the query that started them, so it
/// sits in its own `Arc` that each refresh task holds a clone of.
struct Resolver<U: Upstream> {
    cache: Cache,
    upstreams: Upstreams<U>,
    inflight: Semaphore,
    /// Keys with a background refresh running, so a busy stale name refreshes once.
    refreshing: Mutex<HashSet<CacheKey>>,
}

impl<U: Upstream + 'static> Resolver<U> {
    /// The one way to ask upstream, for queries and refreshes alike. Over the cap the
    /// answer is an immediate error, not a wait: queueing behind a slow upstream would
    /// only turn an outage into a pile of late answers nobody is waiting for.
    async fn fetch(&self, q: &Message) -> Result<(Message, ServedFrom, String), FetchError> {
        let Ok(_permit) = self.inflight.try_acquire() else {
            return Err(FetchError::Busy);
        };
        self.upstreams.resolve(q).await.map_err(FetchError::Failed)
    }
}

/// What `decide` did, before it becomes a `QueryRecord`.
struct Decision {
    outcome: Outcome,
    reason: Reason,
    served_from: ServedFrom,
    rule: Option<(u32, Arc<str>)>,
    upstream: Option<String>,
}

impl Decision {
    fn local(outcome: Outcome, reason: Reason) -> Self {
        Decision {
            outcome,
            reason,
            served_from: ServedFrom::Local,
            rule: None,
            upstream: None,
        }
    }

    fn by_rule(outcome: Outcome, reason: Reason, list_id: u32, rule: Arc<str>) -> Self {
        Decision {
            rule: Some((list_id, rule)),
            ..Decision::local(outcome, reason)
        }
    }
}

pub struct Pipeline<U: Upstream = Remote> {
    rules: Shared<RuleSet>,
    live: Shared<LiveConfig>,
    resolver: Arc<Resolver<U>>,
    paused_until: Mutex<Option<Instant>>,
}

impl<U: Upstream + 'static> Pipeline<U> {
    pub fn new(
        rules: Shared<RuleSet>,
        live: Shared<LiveConfig>,
        upstreams: Upstreams<U>,
        max_inflight: usize,
    ) -> Self {
        Pipeline {
            rules,
            live,
            resolver: Arc::new(Resolver {
                cache: Cache::new(CACHE_ENTRIES),
                upstreams,
                inflight: Semaphore::new(max_inflight),
                refreshing: Mutex::new(HashSet::new()),
            }),
            paused_until: Mutex::new(None),
        }
    }

    /// Skip filtering rules for `duration`. Rewrites and refusals still apply.
    #[allow(dead_code)] // Called by Task 12's pause action; tested here.
    pub fn pause(&self, duration: Duration) {
        *lock(&self.paused_until) = Some(now() + duration);
    }

    #[allow(dead_code)] // Called by Task 12's resume action; tested here.
    pub fn resume(&self) {
        *lock(&self.paused_until) = None;
    }

    fn is_paused(&self, at: Instant) -> bool {
        lock(&self.paused_until).is_some_and(|until| at < until)
    }

    pub async fn handle(&self, query: Message, client: IpAddr) -> (Message, QueryRecord) {
        let started = tokio::time::Instant::now();
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        let (name, qtype) = match query.queries.first() {
            Some(q) => (normalize(q.name()), u16::from(q.query_type())),
            None => (String::new(), 0),
        };
        let (resp, d) = self.decide(&query, &name).await;
        let (list_id, rule) = d.rule.unzip();
        let record = QueryRecord {
            ts_ms,
            client,
            name,
            qtype,
            rcode: u16::from(resp.metadata.response_code),
            outcome: d.outcome,
            reason: d.reason,
            list_id,
            rule,
            served_from: d.served_from,
            upstream: d.upstream,
            latency_us: u32::try_from(started.elapsed().as_micros()).unwrap_or(u32::MAX),
            answers: addresses(&resp),
        };
        (resp, record)
    }

    /// The fixed order: ANY, refused names, rewrites, rules on the name, cache, upstream,
    /// CNAME check, cache put.
    async fn decide(&self, query: &Message, name: &str) -> (Message, Decision) {
        let Some(q) = query.queries.first() else {
            let resp = answer::formerr(query.metadata.id);
            return (resp, Decision::local(Outcome::Refused, Reason::None));
        };
        if q.query_type() == RecordType::ANY {
            let d = Decision::local(Outcome::Refused, Reason::AnyQuery);
            return (answer::refused(query), d);
        }
        let live = current(&self.live);
        if live.refused_names.iter().any(|r| same_name(r, name)) {
            let d = Decision::local(Outcome::Refused, Reason::RefusedName);
            return (answer::refused(query), d);
        }
        if let Some(a) = answer::rewrite_for(&live.rewrites, name) {
            let d = Decision::local(Outcome::Rewritten, Reason::None);
            return (answer::rewrite(query, a, REWRITE_TTL), d);
        }

        let at = now();
        let rules = (!self.is_paused(at)).then(|| current(&self.rules));
        let mut allowed_by = None;
        match rules.as_ref().map(|r| r.check(name)) {
            Some(Verdict::Block { list_id, rule }) => {
                let d = Decision::by_rule(Outcome::Blocked, Reason::Rule, list_id, rule);
                return (answer::blocked(query, live.blocked_ttl), d);
            }
            Some(Verdict::HostsIp { ip, list_id, rule }) => {
                let d = Decision::by_rule(Outcome::Rewritten, Reason::Rule, list_id, rule);
                return (answer::hosts_ip(query, ip, live.blocked_ttl), d);
            }
            Some(Verdict::Allow { list_id, rule }) => allowed_by = Some((list_id, rule)),
            Some(Verdict::Pass) | None => {}
        }
        // An allowlisted name skips the CNAME check, as in AdGuard Home: in
        // dnsforward/process.go `processFilteringAfterResponse` returns early for
        // `NotFilteredAllowList`, before any response filtering.
        let cname_rules = if allowed_by.is_some() { None } else { rules };

        let key = cache_key(query, q, name);
        let (resp, served_from, upstream, fetched) = match self.resolver.cache.get(&key, at) {
            Lookup::Fresh(m) => (m, ServedFrom::Cache, None, false),
            Lookup::Stale(m) => {
                self.refresh_in_background(key.clone(), query.clone());
                (m, ServedFrom::StaleCache, None, false)
            }
            Lookup::Miss => match self.resolver.fetch(query).await {
                Ok((m, from, upstream)) => (m, from, Some(upstream), true),
                Err(e) => {
                    warn!(%name, "{e}");
                    let d = Decision {
                        served_from: ServedFrom::Upstream,
                        ..Decision::local(Outcome::Allowed, Reason::None)
                    };
                    return (answer::servfail(query), d);
                }
            },
        };

        // Checked on cache hits too: the rules may have changed since the answer was stored.
        let cname_block = cname_rules.and_then(|r| blocked_cname(&r, &resp));
        if fetched {
            // Stored as received, so a later rule change can still let it through.
            self.resolver.cache.put(key, &resp, now());
        }
        if let Some((list_id, rule)) = cname_block {
            let d = Decision {
                upstream,
                ..Decision::by_rule(Outcome::Blocked, Reason::Cname, list_id, rule)
            };
            return (answer::blocked(query, live.blocked_ttl), d);
        }
        let d = Decision {
            outcome: Outcome::Allowed,
            reason: if allowed_by.is_some() {
                Reason::Rule
            } else {
                Reason::None
            },
            served_from,
            rule: allowed_by,
            upstream,
        };
        (for_client(resp, query), d)
    }

    /// At most one refresh per key runs; it goes through the same capped upstream path.
    fn refresh_in_background(&self, key: CacheKey, query: Message) {
        if !lock(&self.resolver.refreshing).insert(key.clone()) {
            return;
        }
        let resolver = Arc::clone(&self.resolver);
        tokio::spawn(async move {
            match resolver.fetch(&query).await {
                Ok((m, _, _)) => resolver.cache.put(key.clone(), &m, now()),
                Err(e) => warn!(name = %key.name, "background refresh: {e}"),
            }
            lock(&resolver.refreshing).remove(&key);
        });
    }
}

/// Lowercase, without the trailing dot: the form rules, rewrites and the log use.
fn normalize(name: &Name) -> String {
    let mut s = name.to_ascii();
    s.make_ascii_lowercase();
    if s.ends_with('.') {
        s.pop();
    }
    s
}

fn same_name(configured: &str, name: &str) -> bool {
    configured
        .strip_suffix('.')
        .unwrap_or(configured)
        .eq_ignore_ascii_case(name)
}

fn cache_key(query: &Message, q: &hickory_proto::op::Query, name: &str) -> CacheKey {
    CacheKey {
        name: name.into(),
        qtype: u16::from(q.query_type()),
        qclass: u16::from(q.query_class()),
        dnssec_ok: query.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
    }
}

/// The first CNAME target in the answer that the rules block.
fn blocked_cname(rules: &RuleSet, resp: &Message) -> Option<(u32, Arc<str>)> {
    resp.answers.iter().find_map(|r| match &r.data {
        RData::CNAME(CNAME(target)) => match rules.check(&target.to_ascii()) {
            Verdict::Block { list_id, rule } => Some((list_id, rule)),
            _ => None,
        },
        _ => None,
    })
}

/// Fits a cached or upstream answer to this client: its id, its question as written (case
/// included, which 0x20-checking clients compare), its RD bit, and no OPT record unless the
/// client sent one (RFC 6891 6.1.1). The cache key ignores EDNS presence, so an entry filled
/// by an EDNS client can reach one without.
fn for_client(mut resp: Message, query: &Message) -> Message {
    resp.metadata.id = query.metadata.id;
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.queries = query.queries.clone();
    if query.edns.is_none() {
        resp.edns = None;
    }
    resp
}

/// A and AAAA addresses in the answer section.
pub fn addresses(resp: &Message) -> Vec<IpAddr> {
    resp.answers
        .iter()
        .filter_map(|r| match r.data {
            RData::A(A(v4)) => Some(IpAddr::V4(v4)),
            RData::AAAA(AAAA(v6)) => Some(IpAddr::V6(v6)),
            _ => None,
        })
        .collect()
}

/// A scriptable fake upstream, shared by the pipeline and server tests.
#[cfg(test)]
pub mod testing {
    use super::*;
    use anyhow::{bail, Result};
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub const BLOCKED_TTL: u32 = 10;
    /// TTL of every record the fake hands out.
    pub const FAKE_TTL: u32 = 60;

    /// Shared by every fake in one test: how many queries they saw, and whether they are down.
    #[derive(Default)]
    pub struct State {
        pub calls: AtomicUsize,
        pub down: AtomicBool,
    }

    impl State {
        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
        pub fn set_down(&self, down: bool) {
            self.down.store(down, Ordering::SeqCst);
        }
    }

    /// Answers A `192.0.2.<n>` where n counts the queries seen, so a refreshed answer is
    /// told apart from the old one. `a.com` answers `CNAME track.adnet.com` first; names
    /// under `big.` get 40 A records. Down means sleeping far past the 2s deadline.
    pub struct Fake {
        pub name: &'static str,
        pub delay: Duration,
        pub state: Arc<State>,
    }

    impl Upstream for Fake {
        fn name(&self) -> &str {
            self.name
        }

        async fn query(&self, q: &Message) -> Result<Message> {
            let n = self.state.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.state.down.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(30)).await;
                bail!("{} is down", self.name);
            }
            tokio::time::sleep(self.delay).await;
            let mut r = Message::response(q.metadata.id, q.metadata.op_code);
            r.queries = q.queries.clone();
            let Some(question) = q.queries.first() else {
                return Ok(r);
            };
            let mut owner = question.name().clone();
            let text = owner.to_ascii().to_ascii_lowercase();
            if text == "a.com." {
                let target = Name::from_ascii("track.adnet.com.")?;
                r.add_answer(Record::from_rdata(
                    owner,
                    FAKE_TTL,
                    RData::CNAME(CNAME(target.clone())),
                ));
                owner = target;
            }
            let count = if text.starts_with("big.") { 40 } else { 1 };
            for i in 0..count {
                let ip = Ipv4Addr::new(192, 0, 2, (n + i) as u8);
                r.add_answer(Record::from_rdata(owner.clone(), FAKE_TTL, RData::A(A(ip))));
            }
            Ok(r)
        }
    }

    /// One DoH fake and one fallback fake, both on `state`, with the real 1s race timeout.
    pub fn upstreams(state: &Arc<State>, delay: Duration) -> Upstreams<Fake> {
        let fake = |name| Fake {
            name,
            delay,
            state: Arc::clone(state),
        };
        Upstreams::new(
            vec![fake("doh")],
            vec![fake("udp")],
            Duration::from_millis(1000),
        )
    }

    pub fn rewrite(name: &str, a: [u8; 4]) -> Rewrite {
        Rewrite {
            name: name.into(),
            a: a.into(),
        }
    }

    pub fn live() -> LiveConfig {
        LiveConfig {
            rewrites: vec![
                rewrite("home.riddlelab.dev", [192, 168, 0, 107]),
                rewrite("*.home.riddlelab.dev", [192, 168, 0, 107]),
            ],
            refused_names: vec!["version.bind".into(), "id.server".into()],
            blocked_ttl: BLOCKED_TTL,
        }
    }

    /// User rules plus list 1.
    pub fn rules(user: &[&str], list_1: &str) -> Shared<RuleSet> {
        let user: Vec<String> = user.iter().map(|s| s.to_string()).collect();
        shared(RuleSet::build(&user, &[(1, list_1)]).0)
    }

    pub fn pipeline(rules: Shared<RuleSet>, state: &Arc<State>) -> Pipeline<Fake> {
        Pipeline::new(
            rules,
            shared(live()),
            upstreams(state, Duration::from_millis(10)),
            300,
        )
    }

    pub fn query(name: &str, t: RecordType) -> Message {
        let mut m = Message::new(0x4242, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        if let Ok(n) = Name::from_ascii(name) {
            m.add_query(Query::query(n, t));
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, RData, RecordType};
    use std::net::{IpAddr, Ipv4Addr};

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 50));

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn first_a(m: &Message) -> Option<(Ipv4Addr, u32)> {
        m.answers.iter().find_map(|r| match r.data {
            RData::A(A(a)) => Some((a, r.ttl)),
            _ => None,
        })
    }

    #[tokio::test(start_paused = true)]
    async fn rewrite_answers_locally() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], ""), &state);

        let (resp, rec) = p
            .handle(query("Sonder.Home.riddlelab.dev.", RecordType::A), CLIENT)
            .await;
        assert_eq!(resp.metadata.id, 0x4242);
        assert_eq!(first_a(&resp), Some((Ipv4Addr::new(192, 168, 0, 107), 300)));
        assert_eq!(rec.outcome, Outcome::Rewritten);
        assert_eq!(rec.reason, Reason::None);
        assert_eq!(rec.served_from, ServedFrom::Local);
        assert_eq!(rec.name, "sonder.home.riddlelab.dev");
        assert_eq!(rec.qtype, 1);
        assert_eq!(rec.client, CLIENT);
        assert_eq!(rec.answers, vec![ip(192, 168, 0, 107)]);

        let (resp, rec) = p
            .handle(query("home.riddlelab.dev.", RecordType::AAAA), CLIENT)
            .await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
        assert_eq!(rec.outcome, Outcome::Rewritten);
        assert_eq!(state.calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_name_records_rule_and_list() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], "||adnet.com^"), &state);

        let (resp, rec) = p
            .handle(query("ADS.adnet.com.", RecordType::A), CLIENT)
            .await;
        assert_eq!(first_a(&resp), Some((Ipv4Addr::UNSPECIFIED, BLOCKED_TTL)));
        assert_eq!(rec.outcome, Outcome::Blocked);
        assert_eq!(rec.reason, Reason::Rule);
        assert_eq!(rec.list_id, Some(1));
        assert_eq!(rec.rule.as_deref(), Some("||adnet.com^"));
        assert_eq!(rec.served_from, ServedFrom::Local);
        assert_eq!(rec.upstream, None);
        assert_eq!(rec.rcode, 0);
        assert_eq!(rec.answers, vec![ip(0, 0, 0, 0)]);
        assert_eq!(state.calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn hosts_ip_rule_answers_its_address() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], "10.0.0.5 nas.lan"), &state);
        let (resp, rec) = p.handle(query("nas.lan.", RecordType::A), CLIENT).await;
        assert_eq!(
            first_a(&resp),
            Some((Ipv4Addr::new(10, 0, 0, 5), BLOCKED_TTL))
        );
        assert_eq!(rec.outcome, Outcome::Rewritten);
        assert_eq!(rec.reason, Reason::Rule);
        assert_eq!(rec.list_id, Some(1));
        assert_eq!(rec.served_from, ServedFrom::Local);
        assert_eq!(state.calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn allow_rule_resolves_upstream() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&["@@||ok.adnet.com^"], "||adnet.com^"), &state);

        let (resp, rec) = p
            .handle(query("ok.adnet.com.", RecordType::A), CLIENT)
            .await;
        assert_eq!(resp.metadata.id, 0x4242);
        assert_eq!(
            first_a(&resp),
            Some((Ipv4Addr::new(192, 0, 2, 1), FAKE_TTL))
        );
        assert_eq!(rec.outcome, Outcome::Allowed);
        assert_eq!(rec.reason, Reason::Rule);
        assert_eq!(rec.list_id, Some(0));
        assert_eq!(rec.rule.as_deref(), Some("@@||ok.adnet.com^"));
        assert_eq!(rec.served_from, ServedFrom::Upstream);
        assert_eq!(rec.upstream.as_deref(), Some("doh"));
        assert_eq!(rec.answers, vec![ip(192, 0, 2, 1)]);
        assert_eq!(state.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cname_to_blocked_target_is_blocked() {
        let state = Arc::new(State::default());
        let rules = rules(&[], "||adnet.com^");
        let p = pipeline(Arc::clone(&rules), &state);

        let (resp, rec) = p.handle(query("a.com.", RecordType::A), CLIENT).await;
        assert_eq!(first_a(&resp), Some((Ipv4Addr::UNSPECIFIED, BLOCKED_TTL)));
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(rec.outcome, Outcome::Blocked);
        assert_eq!(rec.reason, Reason::Cname);
        assert_eq!(rec.list_id, Some(1));
        assert_eq!(rec.rule.as_deref(), Some("||adnet.com^"));
        assert_eq!(rec.served_from, ServedFrom::Local);

        // The cache holds the answer as received and the check runs again on a hit.
        let (resp, rec) = p.handle(query("a.com.", RecordType::A), CLIENT).await;
        assert_eq!(rec.reason, Reason::Cname);
        assert_eq!(first_a(&resp), Some((Ipv4Addr::UNSPECIFIED, BLOCKED_TTL)));
        assert_eq!(state.calls(), 1);

        // Rules swapped (a list reload) while the answer sits in cache: now it passes.
        *rules.write().unwrap() = Arc::new(RuleSet::default());
        let (resp, rec) = p.handle(query("a.com.", RecordType::A), CLIENT).await;
        assert_eq!(rec.outcome, Outcome::Allowed);
        assert_eq!(rec.served_from, ServedFrom::Cache);
        assert_eq!(resp.answers.len(), 2);
        assert_eq!(state.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn allowlisted_name_skips_the_cname_check() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&["@@||a.com^"], "||adnet.com^"), &state);
        let (resp, rec) = p.handle(query("a.com.", RecordType::A), CLIENT).await;
        assert_eq!(rec.outcome, Outcome::Allowed);
        assert_eq!(rec.reason, Reason::Rule);
        assert_eq!(resp.answers.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn any_is_refused() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], ""), &state);
        let (resp, rec) = p
            .handle(query("example.com.", RecordType::ANY), CLIENT)
            .await;
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
        assert_eq!(rec.outcome, Outcome::Refused);
        assert_eq!(rec.reason, Reason::AnyQuery);
        assert_eq!(rec.served_from, ServedFrom::Local);
        assert_eq!(rec.rcode, 5);
        assert_eq!(state.calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn version_bind_is_refused() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], ""), &state);
        let mut q = query("VERSION.bind.", RecordType::TXT);
        q.queries[0].set_query_class(DNSClass::CH);
        let (resp, rec) = p.handle(q, CLIENT).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
        assert_eq!(rec.outcome, Outcome::Refused);
        assert_eq!(rec.reason, Reason::RefusedName);
        assert_eq!(state.calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn paused_skips_rules() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], "||adnet.com^"), &state);
        p.pause(Duration::from_secs(60));

        let (resp, rec) = p
            .handle(query("ads.adnet.com.", RecordType::A), CLIENT)
            .await;
        assert_eq!(rec.outcome, Outcome::Allowed);
        assert_eq!(rec.reason, Reason::None);
        assert_eq!(rec.served_from, ServedFrom::Upstream);
        assert_eq!(
            first_a(&resp),
            Some((Ipv4Addr::new(192, 0, 2, 1), FAKE_TTL))
        );

        // CNAME uncloaking is a rule check too, so it is off while paused.
        let (_, rec) = p.handle(query("a.com.", RecordType::A), CLIENT).await;
        assert_eq!(rec.outcome, Outcome::Allowed);

        // Rewrites and refusals are not filtering and still apply.
        let (_, rec) = p
            .handle(query("home.riddlelab.dev.", RecordType::A), CLIENT)
            .await;
        assert_eq!(rec.outcome, Outcome::Rewritten);
        let (_, rec) = p.handle(query("id.server.", RecordType::TXT), CLIENT).await;
        assert_eq!(rec.reason, Reason::RefusedName);

        // The pause runs out on its own.
        tokio::time::advance(Duration::from_secs(61)).await;
        let (_, rec) = p.handle(query("x.adnet.com.", RecordType::A), CLIENT).await;
        assert_eq!(rec.outcome, Outcome::Blocked);

        // And resume ends one early.
        p.pause(Duration::from_secs(60));
        p.resume();
        let (_, rec) = p.handle(query("y.adnet.com.", RecordType::A), CLIENT).await;
        assert_eq!(rec.outcome, Outcome::Blocked);
    }

    #[tokio::test(start_paused = true)]
    async fn second_query_is_cache_hit() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], ""), &state);
        let (_, rec) = p.handle(query("example.com.", RecordType::A), CLIENT).await;
        assert_eq!(rec.served_from, ServedFrom::Upstream);

        tokio::time::advance(Duration::from_secs(20)).await;
        let mut q = query("EXAMPLE.com.", RecordType::A);
        q.metadata.id = 0x0707;
        let (resp, rec) = p.handle(q, CLIENT).await;
        assert_eq!(rec.served_from, ServedFrom::Cache);
        assert_eq!(rec.upstream, None);
        assert_eq!(rec.name, "example.com");
        // The cache never sets the id; the pipeline must, and echo the client's question.
        assert_eq!(resp.metadata.id, 0x0707);
        assert_eq!(resp.queries[0].name().to_ascii(), "EXAMPLE.com.");
        assert_eq!(first_a(&resp), Some((Ipv4Addr::new(192, 0, 2, 1), 40)));
        assert_eq!(state.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn upstreams_all_down_serves_stale_then_servfail() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], ""), &state);
        p.handle(query("example.com.", RecordType::A), CLIENT).await;
        tokio::time::advance(Duration::from_secs(u64::from(FAKE_TTL) + 1)).await;
        state.set_down(true);

        let started = tokio::time::Instant::now();
        let (resp, rec) = p.handle(query("example.com.", RecordType::A), CLIENT).await;
        assert_eq!(started.elapsed(), Duration::ZERO, "stale must not wait");
        assert_eq!(rec.served_from, ServedFrom::StaleCache);
        assert_eq!(first_a(&resp), Some((Ipv4Addr::new(192, 0, 2, 1), 30)));

        let started = tokio::time::Instant::now();
        let (resp, rec) = p
            .handle(query("unknown.example.", RecordType::A), CLIENT)
            .await;
        // The fakes sleep 30s; only the 2s deadline inside `resolve` ends the wait.
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(resp.metadata.id, 0x4242);
        assert_eq!(rec.rcode, 2);
        assert_eq!(rec.outcome, Outcome::Allowed);
        assert_eq!(rec.served_from, ServedFrom::Upstream);
        assert_eq!(rec.upstream, None);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_hit_starts_one_background_refresh() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], ""), &state);
        p.handle(query("example.com.", RecordType::A), CLIENT).await;
        tokio::time::advance(Duration::from_secs(u64::from(FAKE_TTL) + 1)).await;

        for _ in 0..3 {
            let (_, rec) = p.handle(query("example.com.", RecordType::A), CLIENT).await;
            assert_eq!(rec.served_from, ServedFrom::StaleCache);
        }
        // Let the refresh (10ms fake) finish.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(state.calls(), 2, "three stale hits, one refresh");

        let (resp, rec) = p.handle(query("example.com.", RecordType::A), CLIENT).await;
        assert_eq!(rec.served_from, ServedFrom::Cache);
        assert_eq!(
            first_a(&resp).map(|(a, _)| a),
            Some(Ipv4Addr::new(192, 0, 2, 2))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn over_inflight_cap_is_servfail() {
        let state = Arc::new(State::default());
        let p = Arc::new(Pipeline::new(
            rules(&[], ""),
            shared(live()),
            upstreams(&state, Duration::from_millis(500)),
            1,
        ));
        let first = tokio::spawn({
            let p = Arc::clone(&p);
            async move { p.handle(query("one.example.", RecordType::A), CLIENT).await }
        });
        // Let the first query take the only permit.
        tokio::time::sleep(Duration::from_millis(1)).await;

        let started = tokio::time::Instant::now();
        let (resp, rec) = p.handle(query("two.example.", RecordType::A), CLIENT).await;
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(rec.served_from, ServedFrom::Upstream);

        let (resp, _) = first.await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        // The permit is back: a third query goes upstream.
        let (resp, _) = p
            .handle(query("three.example.", RecordType::A), CLIENT)
            .await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test(start_paused = true)]
    async fn query_without_question_is_formerr() {
        let state = Arc::new(State::default());
        let p = pipeline(rules(&[], ""), &state);
        let mut q = query("x.example.", RecordType::A);
        q.queries.clear();
        let (resp, rec) = p.handle(q, CLIENT).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::FormErr);
        assert_eq!(resp.metadata.id, 0x4242);
        assert_eq!(rec.rcode, 1);
        assert_eq!(state.calls(), 0);
    }
}
