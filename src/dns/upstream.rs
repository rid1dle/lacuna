//! Upstream resolvers: DoH servers raced against each other, plain UDP/TCP as the fallback.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;

use crate::codes::ServedFrom;
use crate::config::UpstreamConfig;

/// How long one DoH request may take in total (connect, TLS and answer).
/// The race gives up on slow servers sooner; this only bounds the abandoned tail.
const DOH_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Plain DNS to a fallback server: the whole exchange, UDP or TCP.
const FALLBACK_TIMEOUT: Duration = Duration::from_secs(1);
/// Receive buffer for one UDP reply. Replies are bounded by the EDNS size the client
/// advertised, which in practice is 4096 or less.
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

/// RFC 8484 DNS over HTTPS, POST method.
pub struct DohUpstream {
    name: String,
    url: String,
    client: reqwest::Client,
}

impl DohUpstream {
    /// `bootstrap` pins the host to fixed IPs, so reqwest never asks the system resolver
    /// (which on this host is sieve itself and would loop).
    pub fn new(url: &str, bootstrap: &[std::net::IpAddr]) -> Result<Self> {
        let parsed = reqwest::Url::parse(url).with_context(|| format!("bad doh url {url}"))?;
        let host = parsed.host_str().context("doh url has no host")?.to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);
        let mut builder = client_builder().no_proxy().timeout(DOH_REQUEST_TIMEOUT);
        if !bootstrap.is_empty() {
            let addrs: Vec<SocketAddr> =
                bootstrap.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
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
        let mut wire_query = q.clone();
        wire_query.metadata.id = 0;
        let body = wire_query.to_vec().context("encoding query")?;
        let resp = self
            .client
            .post(&self.url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        let bytes = resp.bytes().await?;
        let mut answer = Message::from_vec(&bytes).context("decoding doh answer")?;
        ensure!(
            answer.metadata.message_type == MessageType::Response,
            "doh reply is not a response"
        );
        answer.metadata.id = q.metadata.id;
        Ok(answer)
    }
}

/// Plain DNS over UDP, retried over TCP when the reply is truncated.
pub struct UdpUpstream {
    addr: SocketAddr,
    name: String,
}

impl UdpUpstream {
    pub fn new(addr: SocketAddr) -> Self {
        UdpUpstream { addr, name: format!("udp:{addr}") }
    }

    async fn over_udp(&self, wire: &[u8], id: u16) -> Result<Message> {
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
            match Message::from_vec(&buf[..n]) {
                Ok(m) if m.metadata.id == id && m.metadata.message_type == MessageType::Response => {
                    return Ok(m)
                }
                _ => continue,
            }
        }
    }

    async fn over_tcp(&self, wire: &[u8], id: u16) -> Result<Message> {
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
            m.metadata.id == id && m.metadata.message_type == MessageType::Response,
            "unexpected tcp reply"
        );
        Ok(m)
    }
}

impl Upstream for UdpUpstream {
    fn name(&self) -> &str {
        &self.name
    }

    async fn query(&self, q: &Message) -> Result<Message> {
        let wire = q.to_vec().context("encoding query")?;
        let id = q.metadata.id;
        let exchange = async {
            let m = self.over_udp(&wire, id).await?;
            if m.metadata.truncation {
                self.over_tcp(&wire, id).await
            } else {
                Ok(m)
            }
        };
        tokio::time::timeout(FALLBACK_TIMEOUT, exchange)
            .await
            .map_err(|_| anyhow!("{} timed out", self.name))?
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

/// The DoH race plus the ordered fallback list.
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
        let fallback = cfg.fallback.iter().map(|a| Remote::Udp(UdpUpstream::new(*a))).collect();
        Ok(Self::new(doh, fallback, Duration::from_millis(cfg.race_timeout_ms)))
    }
}

/// Only a definite DNS answer ends the race. SERVFAIL, REFUSED and friends from one
/// server say nothing about whether another can answer.
fn is_answer(m: &Message) -> bool {
    matches!(m.metadata.response_code, ResponseCode::NoError | ResponseCode::NXDomain)
}

impl<U: Upstream + 'static> Upstreams<U> {
    pub fn new(doh: Vec<U>, fallback: Vec<U>, race_timeout: Duration) -> Self {
        Upstreams {
            doh: doh.into_iter().map(Arc::new).collect(),
            fallback: fallback.into_iter().map(Arc::new).collect(),
            race_timeout,
        }
    }

    /// Races every DoH server: the first NOERROR or NXDOMAIN wins and the losers are
    /// cancelled. If none answers in `race_timeout` (or all fail sooner), the fallbacks
    /// are tried in order.
    pub async fn resolve(&self, q: &Message) -> Result<(Message, ServedFrom, String)> {
        if let Some((m, name)) = self.race(q).await {
            return Ok((m, ServedFrom::Upstream, name));
        }
        for u in &self.fallback {
            match u.query(q).await {
                Ok(m) if is_answer(&m) => return Ok((m, ServedFrom::Fallback, u.name().to_string())),
                // A failing fallback only moves on to the next one.
                Ok(_) | Err(_) => continue,
            }
        }
        bail!("no upstream answered")
    }

    async fn race(&self, q: &Message) -> Option<(Message, String)> {
        let mut set = JoinSet::new();
        for u in &self.doh {
            let (u, q) = (Arc::clone(u), q.clone());
            set.spawn(async move { u.query(&q).await.map(|m| (m, u.name().to_string())) });
        }
        let first_answer = async {
            while let Some(joined) = set.join_next().await {
                if let Ok(Ok((m, name))) = joined {
                    if is_answer(&m) {
                        return Some((m, name));
                    }
                }
            }
            None
        };
        // Dropping `set` on return aborts every task still in flight.
        tokio::time::timeout(self.race_timeout, first_answer).await.ok().flatten()
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
        m.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A));
        m
    }

    /// `result: None` makes the fake fail with a transport error.
    struct Fake {
        name: &'static str,
        delay: Duration,
        result: Option<ResponseCode>,
    }

    fn fake(name: &'static str, ms: u64, result: Option<ResponseCode>) -> Fake {
        Fake { name, delay: Duration::from_millis(ms), result }
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

    /// A local DNS server: `script` sees each UDP query and returns the datagrams to send back.
    /// When `tcp_answer` is set, a TCP listener on the same port serves that message.
    async fn serve(
        script: impl Fn(&Message) -> Vec<Vec<u8>> + Send + 'static,
        tcp_answer: Option<Message>,
    ) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = udp.recv_from(&mut buf).await {
                let Ok(q) = Message::from_vec(&buf[..n]) else { continue };
                for d in script(&q) {
                    let _ = udp.send_to(&d, from).await;
                }
            }
        });
        if let Some(answer) = tcp_answer {
            let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
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
    async fn udp_truncated_reply_retries_over_tcp() {
        let mut full = reply(&query(), ResponseCode::NXDomain, false);
        full.metadata.id = 0;
        let addr = serve(|q| vec![reply(q, ResponseCode::NoError, true).to_vec().unwrap()], Some(full)).await;
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
            ("https://dns10.quad9.net/dns-query", ["9.9.9.10".parse().unwrap()]),
            ("https://cloudflare-dns.com/dns-query", ["1.1.1.1".parse().unwrap()]),
        ];
        for (url, bootstrap) in cases {
            let u = DohUpstream::new(url, &bootstrap).unwrap();
            let r = u.query(&query()).await.unwrap_or_else(|e| panic!("{url}: {e:#}"));
            assert_eq!(r.metadata.id, 0x1234, "{url} id restored");
            assert_eq!(r.metadata.response_code, ResponseCode::NoError, "{url}");
            assert!(!r.answers.is_empty(), "{url} returned no A records");
            println!("{} -> {} answers", u.name(), r.answers.len());
        }
    }
}
