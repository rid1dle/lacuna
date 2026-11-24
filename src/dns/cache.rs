//! TTL cache for upstream answers, with optimistic serving of expired entries.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RData;

/// Longest we keep any entry fresh.
const MAX_TTL: u32 = 86_400;
/// TTL put on records served stale, so clients retry soon.
const STALE_TTL: u32 = 30;
/// How long past expiry an entry may still be served stale.
const STALE_WINDOW: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Lowercase query name.
    pub name: Box<str>,
    pub qtype: u16,
    pub qclass: u16,
    /// DNSSEC answers carry extra records, so they must not share an entry with plain ones.
    pub dnssec_ok: bool,
}

#[derive(Debug)]
pub enum Lookup {
    Fresh(Message),
    Stale(Message),
    Miss,
}

pub struct Cache {
    max_entries: usize,
    entries: Mutex<HashMap<CacheKey, Entry>>,
}

struct Entry {
    response: Message,
    expires: Instant,
}

impl Cache {
    pub fn new(max_entries: usize) -> Self {
        Self { max_entries, entries: Mutex::new(HashMap::new()) }
    }

    /// Look `key` up at time `now`.
    ///
    /// The returned message is a clone with every TTL rewritten, but it still carries the id of
    /// the query that filled the cache. The caller must set `metadata.id` to the client's id.
    pub fn get(&self, key: &CacheKey, now: Instant) -> Lookup {
        let mut entries = self.lock();
        let Some(entry) = entries.get(key) else {
            return Lookup::Miss;
        };
        if now < entry.expires {
            // Round up: now < expires, so this is at least 1 and a live entry never shows TTL 0.
            let remaining = (entry.expires - now).as_secs_f64().ceil() as u32;
            return Lookup::Fresh(with_ttl(&entry.response, remaining));
        }
        if now < entry.expires + STALE_WINDOW {
            return Lookup::Stale(with_ttl(&entry.response, STALE_TTL));
        }
        entries.remove(key);
        Lookup::Miss
    }

    /// Store `response` if it is cacheable (NOERROR or NXDOMAIN with a nonzero TTL).
    pub fn put(&self, key: CacheKey, response: &Message, now: Instant) {
        let Some(ttl) = cache_ttl(response) else {
            return;
        };
        let expires = now + Duration::from_secs(u64::from(ttl));
        // Clone before locking so the critical section is only the map update.
        let entry = Entry { response: response.clone(), expires };
        let mut entries = self.lock();
        if !entries.contains_key(&key) && entries.len() >= self.max_entries {
            // A scan is fine at this size; a heap would only pay off if profiling says so.
            let soonest = entries.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| k.clone());
            if let Some(k) = soonest {
                entries.remove(&k);
            }
        }
        entries.insert(key, entry);
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// A panic while holding the lock cannot leave the map half-updated (each operation is a
    /// single insert or remove), so a poisoned lock is safe to keep using.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// How long `response` may be cached, or `None` if it must not be.
fn cache_ttl(response: &Message) -> Option<u32> {
    let ttl = match response.metadata.response_code {
        ResponseCode::NoError if !response.answers.is_empty() => {
            // The whole answer is only as fresh as its shortest-lived record.
            response
                .answers
                .iter()
                .chain(&response.authorities)
                .chain(&response.additionals)
                .map(|r| r.ttl)
                .min()?
        }
        // NXDOMAIN and NODATA (NOERROR, no answers): RFC 2308 section 5 takes the SOA in the
        // authority section, and the lesser of its own TTL and its MINIMUM field.
        ResponseCode::NoError | ResponseCode::NXDomain => response
            .authorities
            .iter()
            .find_map(|r| match &r.data {
                RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
                _ => None,
            })?,
        _ => return None,
    };
    (ttl > 0).then_some(ttl.min(MAX_TTL))
}

/// A clone of `response` with every non-OPT record's TTL set to `ttl`.
fn with_ttl(response: &Message, ttl: u32) -> Message {
    let mut out = response.clone();
    // The OPT pseudo-record lives in `edns`, not in these sections, so it is left alone.
    for r in out.answers.iter_mut().chain(&mut out.authorities).chain(&mut out.additionals) {
        r.ttl = ttl;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn key(name: &str) -> CacheKey {
        CacheKey { name: name.into(), qtype: 1, qclass: 1, dnssec_ok: false }
    }

    fn a_response(ttls: &[u32]) -> Message {
        let mut m = Message::response(7, hickory_proto::op::OpCode::Query);
        for (i, ttl) in ttls.iter().enumerate() {
            let name = Name::from_str("example.com.").unwrap();
            let ip = Ipv4Addr::new(192, 0, 2, i as u8 + 1);
            m.add_answer(Record::from_rdata(name, *ttl, RData::A(A(ip))));
        }
        m
    }

    fn nxdomain(soa_ttl: u32, minimum: u32) -> Message {
        let mut m = Message::response(7, hickory_proto::op::OpCode::Query);
        m.metadata.response_code = ResponseCode::NXDomain;
        let apex = Name::from_str("example.com.").unwrap();
        let soa = SOA::new(apex.clone(), apex.clone(), 1, 0, 0, 0, minimum);
        m.add_authority(Record::from_rdata(apex, soa_ttl, RData::SOA(soa)));
        m
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn answer_ttls(m: &Message) -> Vec<u32> {
        m.answers.iter().map(|r| r.ttl).collect()
    }

    #[test]
    fn fresh_hit_rewrites_ttls_to_remaining_seconds() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        cache.put(key("example.com"), &a_response(&[300, 120]), t0);
        // Entry lives for the smallest TTL (120); 20s in, 100s remain, on every record.
        match cache.get(&key("example.com"), t0 + secs(20)) {
            Lookup::Fresh(m) => assert_eq!(answer_ttls(&m), vec![100, 100]),
            other => panic!("expected Fresh, got {other:?}"),
        }
    }

    #[test]
    fn stale_hit_after_expiry_has_ttl_30() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        cache.put(key("example.com"), &a_response(&[60]), t0);
        match cache.get(&key("example.com"), t0 + secs(61)) {
            Lookup::Stale(m) => assert_eq!(answer_ttls(&m), vec![30]),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn miss_after_expiry_plus_twelve_hours() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        cache.put(key("example.com"), &a_response(&[60]), t0);
        let edge = t0 + secs(60 + 12 * 3600);
        assert!(matches!(cache.get(&key("example.com"), edge - secs(1)), Lookup::Stale(_)));
        assert!(matches!(cache.get(&key("example.com"), edge), Lookup::Miss));
        // The dead entry is dropped on the miss.
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn servfail_and_zero_ttl_are_not_stored() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        let mut servfail = a_response(&[300]);
        servfail.metadata.response_code = ResponseCode::ServFail;
        cache.put(key("a.com"), &servfail, t0);
        cache.put(key("b.com"), &a_response(&[300, 0]), t0);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn at_capacity_evicts_the_soonest_to_expire() {
        let cache = Cache::new(2);
        let t0 = Instant::now();
        cache.put(key("long.com"), &a_response(&[1000]), t0);
        cache.put(key("short.com"), &a_response(&[10]), t0);
        cache.put(key("new.com"), &a_response(&[500]), t0);
        assert_eq!(cache.len(), 2);
        assert!(matches!(cache.get(&key("short.com"), t0), Lookup::Miss));
        assert!(matches!(cache.get(&key("long.com"), t0), Lookup::Fresh(_)));
        assert!(matches!(cache.get(&key("new.com"), t0), Lookup::Fresh(_)));
    }

    #[test]
    fn replacing_a_key_at_capacity_evicts_nothing() {
        let cache = Cache::new(2);
        let t0 = Instant::now();
        cache.put(key("a.com"), &a_response(&[10]), t0);
        cache.put(key("b.com"), &a_response(&[20]), t0);
        cache.put(key("b.com"), &a_response(&[30]), t0);
        assert_eq!(cache.len(), 2);
        assert!(matches!(cache.get(&key("a.com"), t0), Lookup::Fresh(_)));
    }

    #[test]
    fn keys_differ_by_dnssec_ok() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        let mut do_key = key("example.com");
        do_key.dnssec_ok = true;
        cache.put(key("example.com"), &a_response(&[60]), t0);
        assert!(matches!(cache.get(&do_key, t0), Lookup::Miss));
        assert!(matches!(cache.get(&key("example.com"), t0), Lookup::Fresh(_)));
    }

    #[test]
    fn nxdomain_uses_min_of_soa_ttl_and_minimum() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        // SOA minimum 60 is below the record TTL 900: entry lives 60s.
        cache.put(key("gone.com"), &nxdomain(900, 60), t0);
        assert!(matches!(cache.get(&key("gone.com"), t0 + secs(59)), Lookup::Fresh(_)));
        assert!(matches!(cache.get(&key("gone.com"), t0 + secs(60)), Lookup::Stale(_)));
    }

    #[test]
    fn nxdomain_ttl_is_capped_and_needs_an_soa() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        cache.put(key("big.com"), &nxdomain(1_000_000, 1_000_000), t0);
        assert!(matches!(cache.get(&key("big.com"), t0 + secs(86_399)), Lookup::Fresh(_)));
        assert!(matches!(cache.get(&key("big.com"), t0 + secs(86_400)), Lookup::Stale(_)));

        let mut bare = Message::response(7, hickory_proto::op::OpCode::Query);
        bare.metadata.response_code = ResponseCode::NXDomain;
        cache.put(key("nosoa.com"), &bare, t0);
        assert!(matches!(cache.get(&key("nosoa.com"), t0), Lookup::Miss));
    }

    #[test]
    fn ttl_rewrite_covers_authority_and_additional_not_opt() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        let mut m = a_response(&[100]);
        let name = Name::from_str("ns.example.com.").unwrap();
        m.add_authority(Record::from_rdata(name.clone(), 500, RData::A(A(Ipv4Addr::LOCALHOST))));
        m.add_additional(Record::from_rdata(name, 700, RData::A(A(Ipv4Addr::LOCALHOST))));
        m.edns = Some(hickory_proto::op::Edns::new());
        cache.put(key("example.com"), &m, t0);
        let Lookup::Stale(out) = cache.get(&key("example.com"), t0 + secs(100)) else {
            panic!("expected Stale");
        };
        assert_eq!(out.authorities[0].ttl, 30);
        assert_eq!(out.additionals[0].ttl, 30);
        assert!(out.edns.is_some());
    }

    fn nodata(soa_ttl: Option<(u32, u32)>) -> Message {
        let mut m = Message::response(7, hickory_proto::op::OpCode::Query);
        if let Some((ttl, minimum)) = soa_ttl {
            let apex = Name::from_str("example.com.").unwrap();
            let soa = SOA::new(apex.clone(), apex.clone(), 1, 0, 0, 0, minimum);
            m.add_authority(Record::from_rdata(apex, ttl, RData::SOA(soa)));
        }
        m
    }

    #[test]
    fn nodata_is_cached_by_soa_min_and_skipped_without_soa() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        cache.put(key("nodata.com"), &nodata(Some((900, 45))), t0);
        assert!(matches!(cache.get(&key("nodata.com"), t0 + secs(44)), Lookup::Fresh(_)));
        assert!(matches!(cache.get(&key("nodata.com"), t0 + secs(45)), Lookup::Stale(_)));

        cache.put(key("nosoa.com"), &nodata(None), t0);
        assert!(matches!(cache.get(&key("nosoa.com"), t0), Lookup::Miss));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn fractional_remaining_seconds_round_up() {
        let cache = Cache::new(10);
        let t0 = Instant::now();
        cache.put(key("example.com"), &a_response(&[120]), t0);
        match cache.get(&key("example.com"), t0 + Duration::from_millis(20_500)) {
            Lookup::Fresh(m) => assert_eq!(answer_ttls(&m), vec![100]),
            other => panic!("expected Fresh, got {other:?}"),
        }
    }
}
