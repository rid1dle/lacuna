//! Builders for the DNS responses sieve produces itself (blocks, rewrites, errors).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};

use crate::config::Rewrite;

/// TTL for rewrite answers (AdGuard Home's default).
pub const REWRITE_TTL: u32 = 300;

/// UDP payload size we advertise when the client spoke EDNS. 1232 avoids IP fragmentation.
const EDNS_PAYLOAD: u16 = 1232;

/// A response skeleton for `query`: same id, opcode and question, QR and RA set, RD copied.
fn base(query: &Message, code: ResponseCode) -> Message {
    let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = code;
    resp.queries = query.queries.clone();
    // RFC 6891: a responder must answer an OPT with an OPT.
    if query.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        resp.edns = Some(edns);
    }
    resp
}

/// A NOERROR response carrying at most one answer for the first question.
fn with_answer(query: &Message, rdata: Option<RData>, ttl: u32) -> Message {
    let mut resp = base(query, ResponseCode::NoError);
    if let (Some(rdata), Some(q)) = (rdata, query.queries.first()) {
        resp.add_answer(Record::from_rdata(q.name().clone(), ttl, rdata));
    }
    resp
}

fn qtype(query: &Message) -> Option<RecordType> {
    query.queries.first().map(|q| q.query_type())
}

/// The answer for a blocked name: `0.0.0.0` for A, `::` for AAAA, NODATA otherwise.
pub fn blocked(query: &Message, ttl: u32) -> Message {
    let rdata = match qtype(query) {
        Some(RecordType::A) => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
        Some(RecordType::AAAA) => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
        _ => None,
    };
    with_answer(query, rdata, ttl)
}

/// A hosts-file answer: only a query whose type matches the IP's family gets the address.
pub fn hosts_ip(query: &Message, ip: IpAddr, ttl: u32) -> Message {
    let rdata = match (qtype(query), ip) {
        (Some(RecordType::A), IpAddr::V4(v4)) => Some(RData::A(A(v4))),
        (Some(RecordType::AAAA), IpAddr::V6(v6)) => Some(RData::AAAA(AAAA(v6))),
        _ => None,
    };
    with_answer(query, rdata, ttl)
}

/// A local rewrite: A gets the address, every other type is NODATA.
pub fn rewrite(query: &Message, a: Ipv4Addr, ttl: u32) -> Message {
    let rdata = (qtype(query) == Some(RecordType::A)).then(|| RData::A(A(a)));
    with_answer(query, rdata, ttl)
}

pub fn refused(query: &Message) -> Message {
    base(query, ResponseCode::Refused)
}

pub fn servfail(query: &Message) -> Message {
    base(query, ResponseCode::ServFail)
}

/// For a packet too broken to parse: all we know is the id.
pub fn formerr(id: u16) -> Message {
    let mut resp = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr);
    resp.metadata.recursion_available = true;
    resp
}

/// The rewrite address for `name`: an exact rule wins, then the nearest `*.suffix` rule.
/// Case is ignored, as is one trailing dot. `*.x` does not match `x` itself.
pub fn rewrite_for(rewrites: &[Rewrite], name: &str) -> Option<Ipv4Addr> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let find = |wanted: &dyn Fn(&str) -> bool| {
        rewrites
            .iter()
            .find(|r| wanted(r.name.strip_suffix('.').unwrap_or(&r.name)))
            .map(|r| r.a)
    };
    if let Some(a) = find(&|rule| rule.eq_ignore_ascii_case(name)) {
        return Some(a);
    }
    // Walk the parents from nearest to farthest: a.b.c -> b.c -> c.
    let mut rest = name;
    while let Some((_, parent)) = rest.split_once('.') {
        let hit = find(&|rule| {
            rule.strip_prefix("*.")
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(parent))
        });
        if hit.is_some() {
            return hit;
        }
        rest = parent;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, Query};
    use hickory_proto::rr::Name;

    fn query(name: &str, t: RecordType, edns: bool) -> Message {
        let mut m = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
        if edns {
            let mut e = Edns::new();
            e.set_max_payload(4096);
            m.edns = Some(e);
        }
        m
    }

    /// Round-trips through the wire format so the test sees what a client would.
    fn wire(m: &Message) -> Message {
        Message::from_vec(&m.to_vec().unwrap()).unwrap()
    }

    fn check_common(q: &Message, r: &Message, code: ResponseCode) {
        assert_eq!(r.metadata.id, q.metadata.id);
        assert_eq!(r.metadata.message_type, MessageType::Response);
        assert_eq!(r.metadata.op_code, q.metadata.op_code);
        assert_eq!(r.queries, q.queries);
        assert!(r.metadata.recursion_available);
        assert_eq!(r.metadata.recursion_desired, q.metadata.recursion_desired);
        assert_eq!(r.metadata.response_code, code);
        assert!(!r.metadata.authoritative);
    }

    #[test]
    fn blocked_a_and_aaaa() {
        let q = query("ads.example.", RecordType::A, false);
        let r = wire(&blocked(&q, 10));
        check_common(&q, &r, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].ttl, 10);
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

        let q = query("ads.example.", RecordType::AAAA, false);
        let r = wire(&blocked(&q, 10));
        check_common(&q, &r, ResponseCode::NoError);
        assert_eq!(r.answers[0].ttl, 10);
        assert_eq!(r.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn blocked_other_types_are_nodata() {
        let q = query("ads.example.", RecordType::MX, false);
        let r = blocked(&q, 10);
        check_common(&q, &r, ResponseCode::NoError);
        assert!(r.answers.is_empty());
    }

    #[test]
    fn hosts_ip_only_answers_matching_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let qa = query("h.example.", RecordType::A, false);
        let qaaaa = query("h.example.", RecordType::AAAA, false);
        let r = hosts_ip(&qa, v4, 5);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].ttl, 5);
        assert!(hosts_ip(&qaaaa, v4, 5).answers.is_empty());
        assert_eq!(hosts_ip(&qaaaa, v6, 5).answers.len(), 1);
        let r = hosts_ip(&qa, v6, 5);
        check_common(&qa, &r, ResponseCode::NoError);
        assert!(r.answers.is_empty());
    }

    #[test]
    fn rewrite_answers_a_only() {
        let ip = Ipv4Addr::new(192, 168, 1, 107);
        let q = query("sonder.home.", RecordType::A, false);
        let r = rewrite(&q, ip, REWRITE_TTL);
        check_common(&q, &r, ResponseCode::NoError);
        assert_eq!(r.answers[0].ttl, 300);
        assert_eq!(r.answers[0].data, RData::A(A(ip)));

        let q = query("sonder.home.", RecordType::AAAA, false);
        let r = rewrite(&q, ip, REWRITE_TTL);
        check_common(&q, &r, ResponseCode::NoError);
        assert!(r.answers.is_empty());
    }

    #[test]
    fn error_responses() {
        let q = query("x.example.", RecordType::A, false);
        check_common(&q, &refused(&q), ResponseCode::Refused);
        check_common(&q, &servfail(&q), ResponseCode::ServFail);
        let f = formerr(7);
        assert_eq!(f.metadata.id, 7);
        assert_eq!(f.metadata.response_code, ResponseCode::FormErr);
        assert_eq!(f.metadata.message_type, MessageType::Response);
        assert!(f.metadata.recursion_available);
    }

    #[test]
    fn rd_flag_is_copied_not_forced() {
        let mut q = query("x.example.", RecordType::A, false);
        q.metadata.recursion_desired = false;
        let r = blocked(&q, 10);
        assert!(!r.metadata.recursion_desired);
        assert!(r.metadata.recursion_available);
    }

    #[test]
    fn opt_record_only_when_query_had_one() {
        let q = query("x.example.", RecordType::A, true);
        for r in [
            blocked(&q, 1),
            refused(&q),
            servfail(&q),
            rewrite(&q, Ipv4Addr::LOCALHOST, 1),
            hosts_ip(&q, IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        ] {
            let r = wire(&r);
            assert_eq!(r.edns.as_ref().map(Edns::max_payload), Some(1232));
        }
        let q = query("x.example.", RecordType::A, false);
        assert!(wire(&blocked(&q, 1)).edns.is_none());
    }

    #[test]
    fn query_name_case_is_preserved() {
        let q = query("AdS.Example.com.", RecordType::A, false);
        for r in [blocked(&q, 1), rewrite(&q, Ipv4Addr::LOCALHOST, 1)] {
            let r = wire(&r);
            assert_eq!(r.queries[0].name().to_ascii(), "AdS.Example.com.");
            assert_eq!(r.answers[0].name.to_ascii(), "AdS.Example.com.");
        }
    }

    fn rw(name: &str, last: u8) -> Rewrite {
        Rewrite {
            name: name.into(),
            a: Ipv4Addr::new(192, 168, 1, last),
        }
    }

    #[test]
    fn rewrite_for_table() {
        let rules = [
            rw("*.home.riddlelab.dev", 107),
            rw("home.riddlelab.dev", 107),
        ];
        let ip = Some(Ipv4Addr::new(192, 168, 1, 107));
        assert_eq!(rewrite_for(&rules, "sonder.home.riddlelab.dev"), ip);
        assert_eq!(rewrite_for(&rules, "home.riddlelab.dev"), ip);
        assert_eq!(rewrite_for(&rules, "riddlelab.dev"), None);
        assert_eq!(rewrite_for(&rules, "evilhome.riddlelab.dev"), None);
        // Wildcard alone does not cover the apex.
        assert_eq!(rewrite_for(&rules[..1], "home.riddlelab.dev"), None);
    }

    #[test]
    fn rewrite_for_ignores_case_and_trailing_dot() {
        let rules = [rw("*.home.riddlelab.dev", 107)];
        assert!(rewrite_for(&rules, "Sonder.Home.riddlelab.dev.").is_some());
        let rules = [rw("Sonder.Home.RiddleLab.dev", 9)];
        assert_eq!(
            rewrite_for(&rules, "sonder.home.riddlelab.dev."),
            Some(Ipv4Addr::new(192, 168, 1, 9))
        );
    }

    #[test]
    fn rewrite_for_prefers_exact_then_nearest_wildcard() {
        let rules = [rw("*.b.dev", 1), rw("*.a.b.dev", 2), rw("x.a.b.dev", 3)];
        assert_eq!(
            rewrite_for(&rules, "x.a.b.dev"),
            Some(Ipv4Addr::new(192, 168, 1, 3))
        );
        assert_eq!(
            rewrite_for(&rules, "y.a.b.dev"),
            Some(Ipv4Addr::new(192, 168, 1, 2))
        );
        assert_eq!(
            rewrite_for(&rules, "y.b.dev"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }
}
