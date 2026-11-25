//! Upstream resolvers: DoH servers raced against each other, plain UDP/TCP as the fallback.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::future::Future;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use anyhow::bail;
use anyhow::{anyhow, ensure, Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::codes::ServedFrom;
use crate::config::UpstreamConfig;

/// Upper bound for one DoH request (connect, TLS and body). `resolve` stops waiting
/// long before this; the bound only stops a request that outlives its caller's interest.
const DOH_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Short enough that a second bootstrap IP is tried when the first one is blackholed.
const DOH_CONNECT_TIMEOUT: Duration = Duration::from_millis(800);
/// HTTP/2 PING on the pooled DoH connection, idle or not. Without it a connection that
/// died silently (a WAN blip drops the NAT state and no RST arrives) stays in the pool,
/// and queries sent on it time out until TCP notices, which can take minutes.
const DOH_PING_EVERY: Duration = Duration::from_secs(10);
/// No PONG within this closes the connection, so the next query dials a fresh one.
const DOH_PING_TIMEOUT: Duration = Duration::from_secs(3);
/// A DNS message is at most 64 KiB; refuse more from a misbehaving server.
const DOH_MAX_BODY: usize = 64 * 1024;
/// Plain DNS to a fallback server: the whole exchange, UDP or TCP.
const FALLBACK_TIMEOUT: Duration = Duration::from_secs(1);
/// Receive buffer for one UDP reply, and the largest EDNS payload we advertise upstream.
const UDP_BUF: usize = 4096;

/// A reqwest builder that trusts the bundled Mozilla roots and uses the `ring` provider.
/// Shared with list fetching, so there is one TLS setup in the binary.
pub fn client_builder() -> reqwest::ClientBuilder {
    // `Err` means a provider is already installed, which is fine: only ring is compiled in.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|der| reqwest::Certificate::from_der(der).ok());
    reqwest::Client::builder().tls_certs_only(roots)
}

/// One upstream resolver. `impl Future` in a trait (RPITIT) avoids boxing every query
/// and the `async_trait` crate; the cost is that the trait is not object safe, so
/// `Upstreams` is generic over it and production uses the `Remote` enum.
pub trait Upstream: Send + Sync {
    fn name(&self) -> &str;
    fn query(&self, q: &Message) -> impl Future<Output = Result<Message>> + Send;
}

/// A random id for an upstream exchange. A fresh id per query makes blind spoofing
/// harder (RFC 5452). `RandomState` is seeded randomly by the OS, so no rand crate.
fn random_id() -> u16 {
    RandomState::new().build_hasher().finish() as u16
}

/// RFC 5452 9.1: a reply must repeat the question we asked. Names compare ignoring case
/// because servers may change it (0x20 encoding).
fn same_question(sent: &Message, got: &Message) -> bool {
    sent.queries.len() == got.queries.len()
        && sent.queries.iter().zip(&got.queries).all(|(a, b)| {
            a.query_type() == b.query_type()
                && a.query_class() == b.query_class()
                && a.name()
                    .to_ascii()
                    .eq_ignore_ascii_case(&b.name().to_ascii())
        })
}

/// A reply we will accept for `sent`: a response, to our id, to our question.
fn is_valid_reply(sent: &Message, got: &Message) -> bool {
    got.metadata.message_type == MessageType::Response
        && got.metadata.id == sent.metadata.id
        && same_question(sent, got)
}

/// RFC 8484 DNS over HTTPS, POST method.
pub struct DohUpstream {
    name: String,
    url: String,
    client: reqwest::Client,
}

impl DohUpstream {
    /// `bootstrap` pins the host to fixed IPs, so reqwest never asks the system resolver
    /// (which on this host is lacuna itself and would loop). Config validation guarantees
    /// it is non-empty unless the URL host is an IP literal.
    pub fn new(url: &str, bootstrap: &[IpAddr]) -> Result<Self> {
        let parsed = reqwest::Url::parse(url).with_context(|| format!("bad doh url {url}"))?;
        let host = parsed
            .host_str()
            .context("doh url has no host")?
            .to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);
        let mut builder = client_builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(DOH_CONNECT_TIMEOUT)
            .timeout(DOH_REQUEST_TIMEOUT)
            .http2_keep_alive_interval(DOH_PING_EVERY)
            .http2_keep_alive_timeout(DOH_PING_TIMEOUT)
            .http2_keep_alive_while_idle(true);
        if !bootstrap.is_empty() {
            let addrs: Vec<SocketAddr> = bootstrap
                .iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect();
            builder = builder.resolve_to_addrs(&host, &addrs);
        }
        Ok(DohUpstream {
            name: host,
            url: url.to_string(),
            client: builder.build().context("building doh client")?,
        })
    }
}

impl Upstream for DohUpstream {
    fn name(&self) -> &str {
        &self.name
    }

    async fn query(&self, q: &Message) -> Result<Message> {
        // RFC 8484 section 4.1: id 0 keeps identical questions byte-identical for
        // HTTP caches. The caller's id is put back on the way out.
        let mut sent = q.clone();
        sent.metadata.id = 0;
        let body = sent.to_vec().context("encoding query")?;
        let mut resp = self
            .client
            .post(&self.url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        let is_dns = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/dns-message"));
        ensure!(is_dns, "doh reply is not application/dns-message");
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= DOH_MAX_BODY,
                "doh reply over 64 KiB"
            );
            bytes.extend_from_slice(&chunk);
        }
        let mut answer = Message::from_vec(&bytes).context("decoding doh answer")?;
        ensure!(
            is_valid_reply(&sent, &answer),
            "doh reply does not match the query"
        );
        answer.metadata.id = q.metadata.id;
        Ok(answer)
    }
}

/// Plain DNS over UDP, retried over TCP when the reply is truncated.
pub struct UdpUpstream {
    addr: SocketAddr,
    name: String,
    timeout: Duration,
}

impl UdpUpstream {
    pub fn new(addr: SocketAddr) -> Self {
        Self::with_timeout(addr, FALLBACK_TIMEOUT)
    }

    /// For a one-off query (the `ask` command) that can afford a longer wait.
    pub fn with_timeout(addr: SocketAddr, timeout: Duration) -> Self {
        UdpUpstream {
            addr,
            name: format!("udp:{addr}"),
            timeout,
        }
    }

    async fn over_udp(&self, sent: &Message, wire: &[u8]) -> Result<Message> {
        // Bind the wildcard address of the server's family; the OS picks a random port.
        let local: SocketAddr = if self.addr.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let sock = UdpSocket::bind(local).await?;
        sock.send_to(wire, self.addr).await?;
        let mut buf = vec![0u8; UDP_BUF];
        // Stray or spoofed packets are skipped, not errors: keep reading until the
        // caller's timeout fires.
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            if from != self.addr {
                continue;
            }
            if let Ok(m) = Message::from_vec(&buf[..n]) {
                if is_valid_reply(sent, &m) {
                    return Ok(m);
                }
            }
        }
    }

    async fn over_tcp(&self, sent: &Message, wire: &[u8]) -> Result<Message> {
        let mut s = TcpStream::connect(self.addr).await?;
        // DNS over TCP frames each message with a 2-byte big-endian length.
        let len = u16::try_from(wire.len()).context("query too long for tcp")?;
        s.write_all(&len.to_be_bytes()).await?;
        s.write_all(wire).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut buf).await?;
        let m = Message::from_vec(&buf).context("decoding tcp answer")?;
        ensure!(
            is_valid_reply(sent, &m),
            "tcp reply does not match the query"
        );
        Ok(m)
    }
}

impl Upstream for UdpUpstream {
    fn name(&self) -> &str {
        &self.name
    }

    async fn query(&self, q: &Message) -> Result<Message> {
        let mut sent = q.clone();
        sent.metadata.id = random_id();
        // The client may accept more than a UDP reply buffer of ours can hold.
        if let Some(edns) = sent.edns.as_mut() {
            if edns.max_payload() > UDP_BUF as u16 {
                edns.set_max_payload(UDP_BUF as u16);
            }
        }
        let wire = sent.to_vec().context("encoding query")?;
        let exchange = async {
            let m = self.over_udp(&sent, &wire).await?;
            if m.metadata.truncation {
                self.over_tcp(&sent, &wire).await
            } else {
                Ok(m)
            }
        };
        let mut answer = tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| anyhow!("timed out"))??;
        answer.metadata.id = q.metadata.id;
        Ok(answer)
    }
}

/// The production upstream kinds behind one type, so `Upstreams<Remote>` can hold
/// both DoH servers and UDP fallbacks.
pub enum Remote {
    Doh(DohUpstream),
    Udp(UdpUpstream),
}

impl Upstream for Remote {
    fn name(&self) -> &str {
        match self {
            Remote::Doh(u) => u.name(),
            Remote::Udp(u) => u.name(),
        }
    }

    async fn query(&self, q: &Message) -> Result<Message> {
        match self {
            Remote::Doh(u) => u.query(q).await,
            Remote::Udp(u) => u.query(q).await,
        }
    }
}

/// Why `resolve` found no answer: every upstream's failure, so a log line says what
/// happened, plus the last SERVFAIL (if any) so the pipeline can relay a real one.
#[derive(Debug)]
pub struct UpstreamError {
    /// (upstream name, error text or rcode)
    pub failures: Vec<(String, String)>,
    pub last_servfail: Option<Message>,
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no upstream answered")?;
        for (i, (name, why)) in self.failures.iter().enumerate() {
            write!(f, "{} {name}: {why}", if i == 0 { ":" } else { ";" })?;
        }
        Ok(())
    }
}

impl std::error::Error for UpstreamError {}

/// The DoH race plus the fallback servers.
pub struct Upstreams<U: Upstream> {
    // `Arc` so each racing query can run in its own spawned task.
    doh: Vec<Arc<U>>,
    fallback: Vec<Arc<U>>,
    race_timeout: Duration,
}

impl Upstreams<Remote> {
    pub fn from_config(cfg: &UpstreamConfig) -> Result<Self> {
        let doh = cfg
            .doh
            .iter()
            .map(|d| DohUpstream::new(&d.url, &d.bootstrap).map(Remote::Doh))
            .collect::<Result<Vec<_>>>()?;
        let fallback = cfg
            .fallback
            .iter()
            .map(|a| Remote::Udp(UdpUpstream::new(*a)))
            .collect();
        Ok(Self::new(
            doh,
            fallback,
            Duration::from_millis(cfg.race_timeout_ms),
        ))
    }
}

/// Only a definite DNS answer ends the race. SERVFAIL, REFUSED and friends from one
/// server say nothing about whether another can answer.
fn is_answer(m: &Message) -> bool {
    matches!(
        m.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    )
}

type Finished = (String, Result<Message>);

impl<U: Upstream + 'static> Upstreams<U> {
    pub fn new(doh: Vec<U>, fallback: Vec<U>, race_timeout: Duration) -> Self {
        Upstreams {
            doh: doh.into_iter().map(Arc::new).collect(),
            fallback: fallback.into_iter().map(Arc::new).collect(),
            race_timeout,
        }
    }

    /// Worst case is `race_timeout + FALLBACK_TIMEOUT`. All DoH servers start at once.
    /// When none has answered by `race_timeout` (or all have failed sooner), every
    /// fallback starts too and the DoH requests keep running: the first NOERROR or
    /// NXDOMAIN from anyone wins, and dropping the set aborts the rest.
    pub async fn resolve(
        &self,
        q: &Message,
    ) -> Result<(Message, ServedFrom, String), UpstreamError> {
        let start = Instant::now();
        let race_end = start + self.race_timeout;
        let deadline = race_end + FALLBACK_TIMEOUT;

        let mut set: JoinSet<Finished> = JoinSet::new();
        // Names of tasks still running, to blame a timeout on the right upstream.
        let mut pending: Vec<(ServedFrom, String)> = Vec::new();
        let mut err = UpstreamError {
            failures: Vec::new(),
            last_servfail: None,
        };
        spawn_all(&mut set, &mut pending, &self.doh, q, ServedFrom::Upstream);
        let mut fallbacks_started = self.doh.is_empty();
        if fallbacks_started {
            spawn_all(
                &mut set,
                &mut pending,
                &self.fallback,
                q,
                ServedFrom::Fallback,
            );
        }

        loop {
            // Until the fallbacks start, the next wake-up is the race end; after, the deadline.
            let wake = if fallbacks_started {
                deadline
            } else {
                race_end
            };
            match tokio::time::timeout_at(wake, set.join_next()).await {
                Ok(Some(Ok((name, outcome)))) => {
                    let from = take_pending(&mut pending, &name);
                    match outcome {
                        Ok(m) if is_answer(&m) => return Ok((m, from, name)),
                        Ok(m) => {
                            err.failures
                                .push((name, format!("rcode {}", m.metadata.response_code)));
                            if m.metadata.response_code == ResponseCode::ServFail {
                                err.last_servfail = Some(m);
                            }
                        }
                        Err(e) => err.failures.push((name, format!("{e:#}"))),
                    }
                }
                Ok(Some(Err(join_err))) => err
                    .failures
                    .push(("task".to_string(), join_err.to_string())),
                // Nothing left running. Either start the fallbacks now or we are done.
                Ok(None) => {
                    if fallbacks_started {
                        return Err(err);
                    }
                    fallbacks_started = true;
                    spawn_all(
                        &mut set,
                        &mut pending,
                        &self.fallback,
                        q,
                        ServedFrom::Fallback,
                    );
                    if self.fallback.is_empty() {
                        return Err(err);
                    }
                }
                Err(_elapsed) if !fallbacks_started => {
                    fallbacks_started = true;
                    spawn_all(
                        &mut set,
                        &mut pending,
                        &self.fallback,
                        q,
                        ServedFrom::Fallback,
                    );
                }
                Err(_elapsed) => {
                    for (_, name) in pending {
                        err.failures.push((name, "timed out".to_string()));
                    }
                    return Err(err);
                }
            }
        }
    }
}

fn spawn_all<U: Upstream + 'static>(
    set: &mut JoinSet<Finished>,
    pending: &mut Vec<(ServedFrom, String)>,
    upstreams: &[Arc<U>],
    q: &Message,
    from: ServedFrom,
) {
    for u in upstreams {
        let (u, q) = (Arc::clone(u), q.clone());
        pending.push((from, u.name().to_string()));
        set.spawn(async move { (u.name().to_string(), u.query(&q).await) });
    }
}

/// Removes one pending entry called `name` and says which group it belonged to.
fn take_pending(pending: &mut Vec<(ServedFrom, String)>, name: &str) -> ServedFrom {
    match pending.iter().position(|(_, n)| n == name) {
        Some(i) => pending.swap_remove(i).0,
        None => ServedFrom::Upstream,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};

    fn query() -> Message {
        let mut m = Message::new(0x1234, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        m
    }

    /// `result: None` makes the fake fail with a transport error.
    struct Fake {
        name: &'static str,
        delay: Duration,
        result: Option<ResponseCode>,
    }

    fn fake(name: &'static str, ms: u64, result: Option<ResponseCode>) -> Fake {
        Fake {
            name,
            delay: Duration::from_millis(ms),
            result,
        }
    }

    impl Upstream for Fake {
        fn name(&self) -> &str {
            self.name
        }
        async fn query(&self, q: &Message) -> Result<Message> {
            tokio::time::sleep(self.delay).await;
            match self.result {
                Some(code) => {
                    let mut r = Message::response(q.metadata.id, q.metadata.op_code);
                    r.metadata.response_code = code;
                    r.queries = q.queries.clone();
                    Ok(r)
                }
                None => bail!("{} is down", self.name),
            }
        }
    }

    const RACE: Duration = Duration::from_millis(1000);

    #[tokio::test(start_paused = true)]
    async fn fastest_wins() {
        let u = Upstreams::new(
            vec![
                fake("slow", 300, Some(ResponseCode::NoError)),
                fake("fast", 10, Some(ResponseCode::NoError)),
            ],
            vec![],
            RACE,
        );
        let (resp, from, name) = u.resolve(&query()).await.unwrap();
        assert_eq!(name, "fast");
        assert_eq!(from, ServedFrom::Upstream);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test(start_paused = true)]
    async fn nxdomain_counts_as_an_answer() {
        let u = Upstreams::new(
            vec![
                fake("nx", 10, Some(ResponseCode::NXDomain)),
                fake("ok", 300, Some(ResponseCode::NoError)),
            ],
            vec![],
            RACE,
        );
        let (resp, _, name) = u.resolve(&query()).await.unwrap();
        assert_eq!(name, "nx");
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test(start_paused = true)]
    async fn servfail_from_one_does_not_win() {
        let u = Upstreams::new(
            vec![
                fake("bad", 10, Some(ResponseCode::ServFail)),
                fake("good", 300, Some(ResponseCode::NoError)),
            ],
            vec![],
            RACE,
        );
        let (resp, _, name) = u.resolve(&query()).await.unwrap();
        assert_eq!(name, "good");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test(start_paused = true)]
    async fn fallback_after_race_timeout() {
        let u = Upstreams::new(
            vec![fake("doh", 5000, Some(ResponseCode::NoError))],
            vec![fake("udp", 20, Some(ResponseCode::NoError))],
            RACE,
        );
        let (_, from, name) = u.resolve(&query()).await.unwrap();
        assert_eq!(from, ServedFrom::Fallback);
        assert_eq!(name, "udp");
    }

    #[tokio::test(start_paused = true)]
    async fn fallback_when_every_doh_fails_fast() {
        let u = Upstreams::new(
            vec![fake("doh", 5, None)],
            vec![fake("udp", 20, Some(ResponseCode::NoError))],
            RACE,
        );
        let (_, from, _) = u.resolve(&query()).await.unwrap();
        assert_eq!(from, ServedFrom::Fallback);
    }

    #[tokio::test(start_paused = true)]
    async fn all_fail_is_error() {
        let u = Upstreams::new(
            vec![fake("doh", 5, None)],
            vec![
                fake("udp1", 5, None),
                fake("udp2", 5, Some(ResponseCode::ServFail)),
            ],
            RACE,
        );
        assert!(u.resolve(&query()).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn failures_name_every_upstream_and_keep_the_servfail() {
        let u = Upstreams::new(
            vec![
                fake("doh1", 5, None),
                fake("doh2", 6, Some(ResponseCode::ServFail)),
            ],
            vec![fake("udp", 5000, Some(ResponseCode::NoError))],
            RACE,
        );
        let e = u.resolve(&query()).await.unwrap_err();
        let reasons: std::collections::BTreeMap<_, _> = e.failures.iter().cloned().collect();
        assert!(reasons["doh1"].contains("doh1 is down"), "{reasons:?}");
        assert!(reasons["doh2"].contains("Server Failure"), "{reasons:?}");
        assert_eq!(reasons["udp"], "timed out");
        assert_eq!(e.failures.len(), 3);
        assert_eq!(
            e.last_servfail.unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
        let line = u.resolve(&query()).await.unwrap_err().to_string();
        assert!(line.contains("doh1:") && !line.contains('\n'), "{line}");
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_race_plus_fallback_timeout() {
        let u = Upstreams::new(
            vec![fake("doh", 5000, Some(ResponseCode::NoError))],
            vec![
                fake("a", 5000, Some(ResponseCode::NoError)),
                fake("b", 5000, Some(ResponseCode::NoError)),
            ],
            RACE,
        );
        let started = tokio::time::Instant::now();
        assert!(u.resolve(&query()).await.is_err());
        assert_eq!(started.elapsed(), Duration::from_millis(2000));
    }

    #[tokio::test(start_paused = true)]
    async fn late_doh_answer_beats_slower_fallback() {
        let u = Upstreams::new(
            vec![fake("doh", 1050, Some(ResponseCode::NoError))],
            vec![fake("udp", 1500, Some(ResponseCode::NoError))],
            RACE,
        );
        let (_, from, name) = u.resolve(&query()).await.unwrap();
        assert_eq!((from, name.as_str()), (ServedFrom::Upstream, "doh"));
    }

    #[tokio::test(start_paused = true)]
    async fn fail_fast_doh_starts_fallback_at_once() {
        let u = Upstreams::new(
            vec![fake("doh", 5, None)],
            vec![fake("udp", 20, Some(ResponseCode::NoError))],
            RACE,
        );
        let started = tokio::time::Instant::now();
        u.resolve(&query()).await.unwrap();
        assert!(started.elapsed() < RACE);
    }

    /// A local DNS server: `script` sees each UDP query and returns the datagrams to send back.
    /// When `tcp_answer` is set, a TCP listener on the same port serves that message.
    async fn serve(
        script: impl Fn(&Message) -> Vec<Vec<u8>> + Send + 'static,
        tcp_answer: Option<Message>,
    ) -> SocketAddr {
        // The TCP listener must share the UDP port, which the OS picked: retry the pair
        // when another socket already holds that TCP port.
        let mut bound = None;
        for _ in 0..20 {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = udp.local_addr().unwrap();
            if tcp_answer.is_none() {
                bound = Some((udp, addr, None));
                break;
            }
            if let Ok(tcp) = tokio::net::TcpListener::bind(addr).await {
                bound = Some((udp, addr, Some(tcp)));
                break;
            }
        }
        let (udp, addr, tcp) = bound.expect("no free udp+tcp port pair");
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = udp.recv_from(&mut buf).await {
                let Ok(q) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                for d in script(&q) {
                    let _ = udp.send_to(&d, from).await;
                }
            }
        });
        if let (Some(answer), Some(tcp)) = (tcp_answer, tcp) {
            tokio::spawn(async move {
                while let Ok((mut s, _)) = tcp.accept().await {
                    let mut len = [0u8; 2];
                    s.read_exact(&mut len).await.unwrap();
                    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    s.read_exact(&mut q).await.unwrap();
                    let mut a = answer.clone();
                    a.metadata.id = Message::from_vec(&q).unwrap().metadata.id;
                    let w = a.to_vec().unwrap();
                    s.write_all(&(w.len() as u16).to_be_bytes()).await.unwrap();
                    s.write_all(&w).await.unwrap();
                }
            });
        }
        addr
    }

    fn reply(q: &Message, code: ResponseCode, tc: bool) -> Message {
        let mut r = Message::response(q.metadata.id, q.metadata.op_code);
        r.metadata.response_code = code;
        r.metadata.truncation = tc;
        r.queries = q.queries.clone();
        r
    }

    #[tokio::test]
    async fn udp_ignores_stray_packets_then_takes_the_real_answer() {
        let addr = serve(
            |q| {
                let mut wrong_id = reply(q, ResponseCode::ServFail, false);
                wrong_id.metadata.id = q.metadata.id.wrapping_add(1);
                let mut not_response = reply(q, ResponseCode::ServFail, false);
                not_response.metadata.message_type = MessageType::Query;
                vec![
                    b"garbage".to_vec(),
                    wrong_id.to_vec().unwrap(),
                    not_response.to_vec().unwrap(),
                    reply(q, ResponseCode::NoError, false).to_vec().unwrap(),
                ]
            },
            None,
        )
        .await;
        let u = UdpUpstream::new(addr);
        assert_eq!(u.name(), format!("udp:{addr}"));
        let m = u.query(&query()).await.unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn udp_rejects_mismatched_question_then_takes_real_reply() {
        let addr = serve(
            |q| {
                let mut other = reply(q, ResponseCode::ServFail, false);
                other.queries = vec![Query::query(
                    Name::from_ascii("evil.example.").unwrap(),
                    RecordType::A,
                )];
                // Same name in a different case is still the same question.
                let mut shouting = reply(q, ResponseCode::NoError, false);
                shouting.queries = vec![Query::query(
                    Name::from_ascii("EXAMPLE.com.").unwrap(),
                    RecordType::A,
                )];
                vec![other.to_vec().unwrap(), shouting.to_vec().unwrap()]
            },
            None,
        )
        .await;
        let m = UdpUpstream::new(addr).query(&query()).await.unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn udp_uses_fresh_ids_and_restores_the_callers() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let addr = serve(
            move |q| {
                if let Ok(mut ids) = log.lock() {
                    ids.push(q.metadata.id);
                }
                vec![reply(q, ResponseCode::NoError, false).to_vec().unwrap()]
            },
            None,
        )
        .await;
        let u = UdpUpstream::new(addr);
        for _ in 0..8 {
            assert_eq!(u.query(&query()).await.unwrap().metadata.id, 0x1234);
        }
        let ids = seen.lock().unwrap().clone();
        assert!(
            ids.iter().any(|id| *id != 0x1234),
            "ids on the wire: {ids:?}"
        );
    }

    #[tokio::test]
    async fn upstream_sees_do_bit_and_clamped_payload() {
        let seen = Arc::new(std::sync::Mutex::new(None));
        let log = Arc::clone(&seen);
        let addr = serve(
            move |q| {
                if let (Ok(mut slot), Some(e)) = (log.lock(), q.edns.as_ref()) {
                    *slot = Some((e.flags().dnssec_ok, e.max_payload()));
                }
                vec![reply(q, ResponseCode::NoError, false).to_vec().unwrap()]
            },
            None,
        )
        .await;
        let mut q = query();
        let mut e = hickory_proto::op::Edns::new();
        e.set_dnssec_ok(true);
        e.set_max_payload(65_000);
        q.edns = Some(e);
        UdpUpstream::new(addr).query(&q).await.unwrap();
        assert_eq!(*seen.lock().unwrap(), Some((true, 4096)));
    }

    #[tokio::test]
    async fn udp_truncated_reply_retries_over_tcp() {
        let mut full = reply(&query(), ResponseCode::NXDomain, false);
        full.metadata.id = 0;
        let addr = serve(
            |q| vec![reply(q, ResponseCode::NoError, true).to_vec().unwrap()],
            Some(full),
        )
        .await;
        let m = UdpUpstream::new(addr).query(&query()).await.unwrap();
        // NXDOMAIN can only have come from the TCP side.
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(m.metadata.id, 0x1234);
        assert!(!m.metadata.truncation);
    }

    #[tokio::test]
    async fn udp_silent_server_times_out() {
        let addr = serve(|_| vec![], None).await;
        let started = std::time::Instant::now();
        assert!(UdpUpstream::new(addr).query(&query()).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    /// Needs the network: run with `-- --ignored live_doh_quad9_and_cloudflare`.
    #[tokio::test]
    #[ignore]
    async fn live_doh_quad9_and_cloudflare() {
        let cases: [(&str, [std::net::IpAddr; 1]); 2] = [
            (
                "https://dns10.quad9.net/dns-query",
                ["9.9.9.10".parse().unwrap()],
            ),
            (
                "https://cloudflare-dns.com/dns-query",
                ["1.1.1.1".parse().unwrap()],
            ),
        ];
        for (url, bootstrap) in cases {
            let u = DohUpstream::new(url, &bootstrap).unwrap();
            let r = u
                .query(&query())
                .await
                .unwrap_or_else(|e| panic!("{url}: {e:#}"));
            assert_eq!(r.metadata.id, 0x1234, "{url} id restored");
            assert_eq!(r.metadata.response_code, ResponseCode::NoError, "{url}");
            assert!(!r.answers.is_empty(), "{url} returned no A records");
            println!("{} -> {} answers", u.name(), r.answers.len());
        }
    }
}
