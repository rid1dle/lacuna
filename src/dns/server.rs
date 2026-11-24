//! UDP and TCP listeners feeding the pipeline.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::{Message, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use super::answer;
use super::pipeline::{LogSink, Pipeline};
use super::upstream::Upstream;

/// How long a TCP client has to send its next query, to finish each frame, and to take
/// each answer off our hands.
const TCP_IDLE: Duration = Duration::from_secs(10);
/// Largest UDP message read or sent, whatever a client's EDNS asks for. A longer
/// datagram is cut short by the kernel and then fails to parse.
const UDP_MAX: usize = 4096;
/// Open TCP connections at once; more are closed as soon as they are accepted.
const TCP_MAX_CONNECTIONS: usize = 128;
/// Pause after a failed accept or receive, so a persistent error cannot spin a core.
const ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Both sockets, bound before serving so the caller can learn the real address.
pub struct Listeners {
    udp: UdpSocket,
    tcp: TcpListener,
}

impl Listeners {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let udp = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding udp {addr}"))?;
        // With port 0 the OS picked one for UDP; TCP must listen on the same port.
        let addr = udp.local_addr()?;
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding tcp {addr}"))?;
        Ok(Listeners { udp, tcp })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.udp.local_addr()?)
    }
}

/// Serves DNS on both sockets until the task is dropped.
pub async fn run<U: Upstream + 'static>(
    pipeline: Arc<Pipeline<U>>,
    listeners: Listeners,
    log: Arc<dyn LogSink>,
) {
    tokio::join!(
        serve_udp(Arc::clone(&pipeline), listeners.udp, Arc::clone(&log)),
        serve_tcp(pipeline, listeners.tcp, log),
    );
}

/// What to do with one packet.
enum Incoming {
    Query(Message),
    /// Unparseable, but long enough to carry an id to answer to.
    FormErr(u16),
    Drop,
}

fn classify(bytes: &[u8]) -> Incoming {
    // QR is the top bit of byte 2. A response is never answered, parseable or not:
    // two servers replying to each other's replies would loop forever.
    if bytes.get(2).is_some_and(|b| b & 0x80 != 0) {
        return Incoming::Drop;
    }
    match (Message::from_vec(bytes), bytes) {
        (Ok(m), _) => Incoming::Query(m),
        (Err(_), [hi, lo, ..]) => Incoming::FormErr(u16::from_be_bytes([*hi, *lo])),
        (Err(_), _) => Incoming::Drop,
    }
}

/// Runs one packet through the pipeline, logs it, and encodes the reply.
async fn respond<U: Upstream + 'static>(
    pipeline: &Pipeline<U>,
    log: &dyn LogSink,
    bytes: &[u8],
    client: IpAddr,
    udp: bool,
) -> Option<Vec<u8>> {
    let query = match classify(bytes) {
        Incoming::Query(q) => q,
        Incoming::FormErr(id) => return answer::formerr(id).to_vec().ok(),
        Incoming::Drop => return None,
    };
    // `max_payload` is the client's EDNS size, or 512 without EDNS (RFC 1035 4.2.1).
    let limit = if udp {
        usize::from(query.max_payload()).min(UDP_MAX)
    } else {
        usize::from(u16::MAX)
    };
    let (resp, mut record) = pipeline.handle(query, client).await;
    let encoded = encode(&resp, limit);
    // The row lists what the client got: no addresses when the records were dropped.
    if !matches!(encoded, Some((_, Sent::Whole))) {
        record.answers.clear();
    }
    log.send(record);
    encoded.map(|(wire, _)| wire)
}

/// Whether the encoded reply carries the response's records.
enum Sent {
    Whole,
    /// Truncated, or replaced by SERVFAIL: no records went out.
    WithoutRecords,
}

/// Encodes `resp`. Past `limit` bytes it goes out truncated (TC set, records dropped),
/// which tells the client to ask again over TCP.
fn encode(resp: &Message, limit: usize) -> Option<(Vec<u8>, Sent)> {
    let wire = match resp.to_vec() {
        Ok(wire) if wire.len() <= limit => return Some((wire, Sent::Whole)),
        Ok(_) => resp.truncate().to_vec().ok(),
        Err(e) => {
            warn!("encoding response: {e}");
            let mut failed = resp.truncate();
            failed.metadata.truncation = false;
            failed.metadata.response_code = ResponseCode::ServFail;
            failed.to_vec().ok()
        }
    };
    wire.map(|w| (w, Sent::WithoutRecords))
}

/// One socket; each datagram is handled in its own task so a slow upstream answer never
/// holds up the next query.
async fn serve_udp<U: Upstream + 'static>(
    pipeline: Arc<Pipeline<U>>,
    sock: UdpSocket,
    log: Arc<dyn LogSink>,
) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; UDP_MAX];
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(got) => got,
            // Linux reports an ICMP error for an earlier send here; the socket is fine.
            Err(e) => {
                debug!("udp recv: {e}");
                tokio::time::sleep(ERROR_BACKOFF).await;
                continue;
            }
        };
        let bytes = buf[..n].to_vec();
        let (pipeline, sock, log) = (Arc::clone(&pipeline), Arc::clone(&sock), Arc::clone(&log));
        tokio::spawn(async move {
            if let Some(reply) = respond(&pipeline, &*log, &bytes, from.ip(), true).await {
                if let Err(e) = sock.send_to(&reply, from).await {
                    debug!(%from, "udp send: {e}");
                }
            }
        });
    }
}

async fn serve_tcp<U: Upstream + 'static>(
    pipeline: Arc<Pipeline<U>>,
    listener: TcpListener,
    log: Arc<dyn LogSink>,
) {
    let slots = Arc::new(Semaphore::new(TCP_MAX_CONNECTIONS));
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Over the cap the stream is dropped here, which closes it.
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    debug!(%peer, "tcp connection cap reached");
                    continue;
                };
                let (pipeline, log) = (Arc::clone(&pipeline), Arc::clone(&log));
                tokio::spawn(async move {
                    connection(&pipeline, &*log, stream, peer.ip()).await;
                    drop(slot);
                });
            }
            Err(e) => {
                // Usually out of file descriptors.
                warn!("tcp accept: {e}");
                tokio::time::sleep(ERROR_BACKOFF).await;
            }
        }
    }
}

/// DNS over TCP frames each message with a 2-byte big-endian length (RFC 1035 4.2.2).
/// Queries on one connection are answered in order. The connection closes when the
/// client closes it, after `TCP_IDLE` with no new query, when a frame stalls or is empty,
/// or when the client stops reading answers.
async fn connection<U: Upstream + 'static>(
    pipeline: &Pipeline<U>,
    log: &dyn LogSink,
    mut stream: TcpStream,
    client: IpAddr,
) {
    loop {
        let mut len = [0u8; 2];
        if !read_in_time(&mut stream, &mut len).await {
            return;
        }
        let len = usize::from(u16::from_be_bytes(len));
        if len == 0 {
            return;
        }
        let mut frame = vec![0u8; len];
        if !read_in_time(&mut stream, &mut frame).await {
            return;
        }
        let Some(reply) = respond(pipeline, log, &frame, client, false).await else {
            continue;
        };
        // `encode` capped the reply at u16::MAX bytes, so this never fails.
        let Ok(reply_len) = u16::try_from(reply.len()) else {
            return;
        };
        // One write, so the length and the message leave in the same segment.
        let mut out = Vec::with_capacity(2 + reply.len());
        out.extend_from_slice(&reply_len.to_be_bytes());
        out.extend_from_slice(&reply);
        let written = tokio::time::timeout(TCP_IDLE, stream.write_all(&out)).await;
        if !matches!(written, Ok(Ok(()))) {
            return;
        }
    }
}

/// Fills `buf` within `TCP_IDLE`; false on timeout, error or a closed connection.
async fn read_in_time(stream: &mut TcpStream, buf: &mut [u8]) -> bool {
    matches!(
        tokio::time::timeout(TCP_IDLE, stream.read_exact(buf)).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::pipeline::shared;
    use crate::dns::pipeline::testing::{live, query, rules, upstreams, State};
    use crate::dns::pipeline::QueryRecord;
    use hickory_proto::op::Message;
    use hickory_proto::op::{Edns, MessageType, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, RecordType};
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Keeps every record, so a test can see that the server logs what it answers.
    #[derive(Default)]
    struct Collect(Mutex<Vec<QueryRecord>>);

    impl LogSink for Collect {
        fn send(&self, r: QueryRecord) {
            self.0.lock().unwrap().push(r);
        }
    }

    const WAIT: Duration = Duration::from_secs(3);

    async fn start() -> (SocketAddr, Arc<Collect>) {
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
        let log = Arc::new(Collect::default());
        tokio::spawn(run(p, listeners, Arc::clone(&log) as Arc<dyn LogSink>));
        (addr, log)
    }

    async fn udp_client() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    /// Sends `bytes` and waits up to `wait` for one reply.
    async fn udp_exchange(
        sock: &UdpSocket,
        to: SocketAddr,
        bytes: &[u8],
        wait: Duration,
    ) -> Option<Vec<u8>> {
        sock.send_to(bytes, to).await.unwrap();
        let mut buf = vec![0u8; 65_535];
        match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    async fn tcp_send(s: &mut TcpStream, bytes: &[u8]) {
        s.write_all(&(bytes.len() as u16).to_be_bytes())
            .await
            .unwrap();
        s.write_all(bytes).await.unwrap();
    }

    async fn tcp_recv(s: &mut TcpStream) -> Message {
        let read = async {
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await?;
            let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
            s.read_exact(&mut buf).await?;
            Ok::<_, std::io::Error>(buf)
        };
        let buf = tokio::time::timeout(WAIT, read).await.unwrap().unwrap();
        Message::from_vec(&buf).unwrap()
    }

    fn home_a(m: &Message) -> bool {
        m.answers
            .iter()
            .any(|r| r.data == RData::A(A(Ipv4Addr::new(192, 168, 0, 107))))
    }

    fn wire(name: &str, id: u16) -> Vec<u8> {
        let mut q = query(name, RecordType::A);
        q.metadata.id = id;
        q.to_vec().unwrap()
    }

    #[tokio::test]
    async fn answers_over_udp_and_tcp() {
        let (addr, log) = start().await;

        let sock = udp_client().await;
        let reply = udp_exchange(&sock, addr, &wire("home.riddlelab.dev.", 11), WAIT)
            .await
            .expect("udp reply");
        let m = Message::from_vec(&reply).unwrap();
        assert_eq!(m.metadata.id, 11);
        assert!(home_a(&m));

        // Two queries on one TCP connection.
        let mut s = TcpStream::connect(addr).await.unwrap();
        for id in [12, 13] {
            tcp_send(&mut s, &wire("x.home.riddlelab.dev.", id)).await;
            let m = tcp_recv(&mut s).await;
            assert_eq!(m.metadata.id, id);
            assert!(home_a(&m));
        }

        let names: Vec<String> = log
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.name.clone())
            .collect();
        assert_eq!(
            names,
            [
                "home.riddlelab.dev",
                "x.home.riddlelab.dev",
                "x.home.riddlelab.dev"
            ]
        );
    }

    #[tokio::test]
    async fn malformed_packets_do_not_kill_server() {
        let (addr, log) = start().await;
        let sock = udp_client().await;

        // Too short to parse, but it has an id: FORMERR with that id.
        let reply = udp_exchange(&sock, addr, &[0x01, 0x02, 0x03], WAIT)
            .await
            .expect("formerr reply");
        let m = Message::from_vec(&reply).unwrap();
        assert_eq!(m.metadata.id, 0x0102);
        assert_eq!(m.metadata.response_code, ResponseCode::FormErr);

        // One byte has no id: dropped.
        assert!(
            udp_exchange(&sock, addr, &[0x07], Duration::from_millis(200))
                .await
                .is_none()
        );

        // A response sent as a query is dropped, parseable or not.
        let mut resp = query("home.riddlelab.dev.", RecordType::A);
        resp.metadata.message_type = MessageType::Response;
        let short = Duration::from_millis(200);
        assert!(udp_exchange(&sock, addr, &resp.to_vec().unwrap(), short)
            .await
            .is_none());
        assert!(udp_exchange(&sock, addr, &[0x01, 0x02, 0x80], short)
            .await
            .is_none());

        // A TCP frame claiming 65535 bytes, 3 bytes sent, then closed.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[0xFF, 0xFF, 1, 2, 3]).await.unwrap();
        drop(s);

        // Still answering on both transports.
        let reply = udp_exchange(&sock, addr, &wire("home.riddlelab.dev.", 21), WAIT)
            .await
            .expect("udp still answers");
        assert!(home_a(&Message::from_vec(&reply).unwrap()));
        let mut s = TcpStream::connect(addr).await.unwrap();
        tcp_send(&mut s, &wire("home.riddlelab.dev.", 22)).await;
        assert!(home_a(&tcp_recv(&mut s).await));
        // Garbage never reaches the log.
        assert_eq!(log.0.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn udp_truncates_to_client_payload() {
        let (addr, log) = start().await;
        let sock = udp_client().await;

        // 40 A records do not fit in 512 bytes: TC set, answers dropped.
        let reply = udp_exchange(&sock, addr, &wire("big.example.", 31), WAIT)
            .await
            .unwrap();
        assert!(reply.len() <= 512);
        let m = Message::from_vec(&reply).unwrap();
        assert!(m.metadata.truncation);
        assert!(m.answers.is_empty());
        assert_eq!(m.metadata.id, 31);
        // The log row lists what was sent, which is nothing.
        let row = log.0.lock().unwrap().last().cloned().unwrap();
        assert!(row.answers.is_empty(), "{:?}", row.answers);

        // With EDNS 4096 the same answer fits.
        let mut q = query("big.example.", RecordType::A);
        q.metadata.id = 32;
        let mut e = Edns::new();
        e.set_max_payload(4096);
        q.edns = Some(e);
        let reply = udp_exchange(&sock, addr, &q.to_vec().unwrap(), WAIT)
            .await
            .unwrap();
        let m = Message::from_vec(&reply).unwrap();
        assert!(!m.metadata.truncation);
        assert_eq!(m.answers.len(), 40);
        assert_eq!(log.0.lock().unwrap().last().unwrap().answers.len(), 40);

        // TCP has no such limit.
        let mut s = TcpStream::connect(addr).await.unwrap();
        tcp_send(&mut s, &wire("big.example.", 33)).await;
        let m = tcp_recv(&mut s).await;
        assert!(!m.metadata.truncation);
        assert_eq!(m.answers.len(), 40);
    }

    /// Paused time: the 10s idle timeout fires as soon as the runtime has nothing else to do.
    #[tokio::test(start_paused = true)]
    async fn tcp_idle_and_stalled_connections_are_closed() {
        let (addr, _) = start().await;

        for opening in [&[][..], &[0x00, 0x20, 1, 2, 3][..]] {
            let started = tokio::time::Instant::now();
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(opening).await.unwrap();
            let mut buf = [0u8; 16];
            // 0 bytes read means the server closed the connection.
            let read = tokio::time::timeout(Duration::from_secs(60), s.read(&mut buf)).await;
            assert_eq!(read.expect("closed before 60s").unwrap(), 0);
            assert!(started.elapsed() >= Duration::from_secs(10));
        }
    }

    /// A client that sends queries but never reads: once the socket buffers fill, the
    /// server's write stalls and must give up after TCP_IDLE instead of holding the
    /// connection forever. Each `huge.` answer is about 32 KB; 600 of them are far more
    /// than loopback buffers hold, so the server can only finish by timing out.
    #[tokio::test(start_paused = true)]
    async fn tcp_client_that_never_reads_is_dropped() {
        const SENT: usize = 600;
        let (addr, _) = start().await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut burst = Vec::new();
        for id in 0..SENT as u16 {
            let q = wire("huge.example.", id);
            burst.extend_from_slice(&(q.len() as u16).to_be_bytes());
            burst.extend_from_slice(&q);
        }
        s.write_all(&burst).await.unwrap();
        // Paused time jumps ahead whenever everything is blocked.
        tokio::time::sleep(Duration::from_secs(60)).await;

        // Now drain. A server that gave up sent fewer answers than queries.
        let mut answered = 0;
        loop {
            let mut len = [0u8; 2];
            if s.read_exact(&mut len).await.is_err() {
                break;
            }
            let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
            if s.read_exact(&mut body).await.is_err() {
                break;
            }
            answered += 1;
        }
        assert!(
            answered > 0 && answered < SENT,
            "answered {answered} of {SENT}"
        );
    }

    /// EOF or reset within 2s, well before the 10s idle timeout.
    async fn closed_soon(mut s: TcpStream) -> bool {
        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
        matches!(read, Ok(Ok(0)) | Ok(Err(_)))
    }

    #[tokio::test]
    async fn tcp_empty_frame_closes_the_connection() {
        let (addr, _) = start().await;
        // A zero-length frame is not a DNS message.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[0, 0]).await.unwrap();
        assert!(closed_soon(s).await, "empty frame kept open");
    }

    #[tokio::test]
    async fn tcp_connections_over_the_cap_are_closed() {
        let (addr, _) = start().await;
        let mut held = Vec::new();
        for _ in 0..TCP_MAX_CONNECTIONS {
            held.push(TcpStream::connect(addr).await.unwrap());
        }
        // Give the server time to accept them all.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let over = TcpStream::connect(addr).await.unwrap();
        assert!(closed_soon(over).await, "connection over the cap kept open");

        // Freed slots are reused.
        drop(held);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        tcp_send(&mut s, &wire("home.riddlelab.dev.", 41)).await;
        assert!(home_a(&tcp_recv(&mut s).await));
    }
}
