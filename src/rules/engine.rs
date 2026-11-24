//! The rule set: every list's rules in one map, queried by walking a name's suffixes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use super::{parse_line, Parsed, Rule, RuleKind};

/// What the rules say about one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Block {
        list_id: u32,
        rule: Arc<str>,
    },
    Allow {
        list_id: u32,
        rule: Arc<str>,
    },
    HostsIp {
        ip: IpAddr,
        list_id: u32,
        rule: Arc<str>,
    },
}

/// Per-list parse outcome, for the list manager to store and show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListStats {
    pub list_id: u32,
    pub parsed: usize,
    /// Keyed by `SkipReason::label()`.
    pub skipped: BTreeMap<String, usize>,
}

/// Where a rule came from and its text; lives in the arena, referenced by index.
#[derive(Debug)]
struct Origin {
    list_id: u32,
    rule: Arc<str>,
}

/// 1-based index into `RuleSet::origins`; `None` costs nothing extra thanks to the niche.
type Slot = Option<NonZeroU32>;

/// The strongest rule of each class for one exact domain (first loaded wins a tie).
/// Four 4-byte indices instead of owned rule text keeps a 200k-domain table small.
#[derive(Debug, Default)]
struct Entry {
    important_allow: Slot,
    important_block: Slot,
    allow: Slot,
    block: Slot,
}

impl Entry {
    fn insert(&mut self, kind: &RuleKind, important: bool, index: NonZeroU32) {
        let slot = match (kind, important) {
            (RuleKind::Allow, true) => &mut self.important_allow,
            (RuleKind::Block, true) => &mut self.important_block,
            (RuleKind::Allow, false) => &mut self.allow,
            (RuleKind::Block, false) => &mut self.block,
            // Hosts IPs never reach an Entry; they live in `RuleSet::hosts_ip`.
            (RuleKind::HostsIp(_), _) => return,
        };
        slot.get_or_insert(index);
    }
}

/// Immutable once built; share it as `Arc<RuleSet>` and swap the Arc to reload.
#[derive(Debug, Default)]
pub struct RuleSet {
    origins: Vec<Origin>,
    /// Rules that cover the name and every subdomain (`||domain^`, plain domains).
    suffix: HashMap<Box<str>, Entry>,
    /// Hosts-syntax null-IP blocks: the exact name only.
    exact_block: HashMap<Box<str>, NonZeroU32>,
    /// Hosts-syntax lines with a real IP: the exact name only. Rare, so a plain map.
    hosts_ip: HashMap<Box<str>, (IpAddr, NonZeroU32)>,
    count: usize,
}

/// The exact rule `text` cancels: itself without the `badfilter` modifier.
fn badfilter_twin(text: &str) -> String {
    let Some((head, mods)) = text.split_once('$') else {
        return text.to_string();
    };
    let kept: Vec<&str> = mods.split(',').filter(|m| *m != "badfilter").collect();
    if kept.is_empty() {
        head.to_string()
    } else {
        format!("{head}${}", kept.join(","))
    }
}

/// Parse every line into `rules`, counting skips; blank lines count as neither.
fn parse_into<'a>(
    list_id: u32,
    lines: impl Iterator<Item = &'a str>,
    rules: &mut Vec<(u32, Rule)>,
) -> ListStats {
    let mut st = ListStats {
        list_id,
        parsed: 0,
        skipped: BTreeMap::new(),
    };
    for line in lines {
        match parse_line(line) {
            Parsed::Rule(rule) => {
                st.parsed += 1;
                rules.push((list_id, rule));
            }
            Parsed::Skip(reason) => *st.skipped.entry(reason.label()).or_insert(0) += 1,
            Parsed::Blank => {}
        }
    }
    st
}

impl RuleSet {
    /// User rules are list 0 and load first, so they win ties against lists.
    pub fn build(user_rules: &[String], lists: &[(u32, &str)]) -> (RuleSet, Vec<ListStats>) {
        let mut rules: Vec<(u32, Rule)> = Vec::new();
        // Each user rule is one line; list bodies are walked in place, never copied.
        let mut stats = vec![parse_into(
            0,
            user_rules.iter().map(String::as_str),
            &mut rules,
        )];
        for (list_id, body) in lists {
            stats.push(parse_into(*list_id, body.lines(), &mut rules));
        }

        // Badfilter applies across lists, so it can only run once every list is read.
        // A user badfilter (list 0) cancels any twin; a list's badfilter cancels list rules only.
        let twins = |from_user: bool| -> HashSet<String> {
            rules
                .iter()
                .filter(|(id, r)| r.badfilter && (*id == 0) == from_user)
                .map(|(_, r)| badfilter_twin(&r.text))
                .collect()
        };
        let (by_user, by_lists) = (twins(true), twins(false));
        let mut set = RuleSet::default();
        for (list_id, rule) in rules {
            let Rule {
                domain,
                kind,
                important,
                badfilter,
                exact_only,
                text,
            } = rule;
            if badfilter || by_user.contains(&text) || (list_id != 0 && by_lists.contains(&text)) {
                continue;
            }
            set.count += 1;
            set.origins.push(Origin {
                list_id,
                rule: Arc::from(text),
            });
            // Safe: the vec was just pushed to, so its length is at least 1.
            let Some(index) = NonZeroU32::new(set.origins.len() as u32) else {
                continue;
            };
            let key = domain.into_boxed_str();
            match (&kind, exact_only) {
                (RuleKind::HostsIp(ip), _) => {
                    set.hosts_ip.entry(key).or_insert((*ip, index));
                }
                (_, true) => {
                    set.exact_block.entry(key).or_insert(index);
                }
                (_, false) => set
                    .suffix
                    .entry(key)
                    .or_default()
                    .insert(&kind, important, index),
            }
        }
        (set, stats)
    }

    pub fn rule_count(&self) -> usize {
        self.count
    }

    /// Rough heap bytes of the tables (slots plus key text plus rule arena), for sizing checks.
    #[allow(dead_code)] // Tests only so far; for sizing checks in Task 15.
    pub fn estimated_bytes(&self) -> usize {
        let keys = |it: &mut dyn Iterator<Item = &Box<str>>| it.map(|k| k.len()).sum::<usize>();
        self.suffix.capacity() * (std::mem::size_of::<(Box<str>, Entry)>() + 1)
            + keys(&mut self.suffix.keys())
            + self.exact_block.capacity() * (std::mem::size_of::<(Box<str>, NonZeroU32)>() + 1)
            + keys(&mut self.exact_block.keys())
            + self.hosts_ip.capacity()
                * (std::mem::size_of::<(Box<str>, (IpAddr, NonZeroU32))>() + 1)
            + self.origins.capacity() * std::mem::size_of::<Origin>()
            + self.origins.iter().map(|o| o.rule.len()).sum::<usize>()
    }

    fn verdict(&self, index: NonZeroU32, make: impl FnOnce(u32, Arc<str>) -> Verdict) -> Verdict {
        // Indices are only ever handed out by `build`, so the lookup cannot miss.
        match self.origins.get(index.get() as usize - 1) {
            Some(o) => make(o.list_id, o.rule.clone()),
            None => Verdict::Pass,
        }
    }

    /// Precedence (AdGuard): important allow, important block, allow, block, hosts IP.
    /// `||example.com^` and plain domains cover every subdomain, so each suffix of the name is
    /// looked up; hosts-syntax lines match the exact name only.
    ///
    /// Plain domain-only lines are treated like `||domain^` (subdomains included). AdGuard's
    /// syntax page (adguard-dns.io/kb/general/dns-filtering-syntax) does not say, so this is
    /// unconfirmed against urlfilter.
    pub fn check(&self, name: &str) -> Verdict {
        // The one allocation: ASCII lowercase of the name, minus a trailing dot.
        let lowered = name.to_ascii_lowercase();
        let full = lowered.strip_suffix('.').unwrap_or(&lowered);

        let (mut imp_block, mut allow, mut block): (Slot, Slot, Slot) = (None, None, None);
        let mut suffix = full;
        loop {
            if let Some(entry) = self.suffix.get(suffix) {
                if let Some(i) = entry.important_allow {
                    return self.verdict(i, |list_id, rule| Verdict::Allow { list_id, rule });
                }
                // The most specific suffix to hit a class wins that class.
                imp_block = imp_block.or(entry.important_block);
                allow = allow.or(entry.allow);
                block = block.or(entry.block);
            }
            match suffix.split_once('.') {
                Some((_, parent)) => suffix = parent,
                None => break,
            }
        }
        block = block.or_else(|| self.exact_block.get(full).copied());

        if let Some(i) = imp_block {
            self.verdict(i, |list_id, rule| Verdict::Block { list_id, rule })
        } else if let Some(i) = allow {
            self.verdict(i, |list_id, rule| Verdict::Allow { list_id, rule })
        } else if let Some(i) = block {
            self.verdict(i, |list_id, rule| Verdict::Block { list_id, rule })
        } else if let Some((ip, i)) = self.hosts_ip.get(full) {
            self.verdict(*i, |list_id, rule| Verdict::HostsIp {
                ip: *ip,
                list_id,
                rule,
            })
        } else {
            Verdict::Pass
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(user: &[&str], lists: &[(u32, &str)]) -> (RuleSet, Vec<ListStats>) {
        let user: Vec<String> = user.iter().map(|s| s.to_string()).collect();
        RuleSet::build(&user, lists)
    }

    fn is_block(v: &Verdict) -> bool {
        matches!(v, Verdict::Block { .. })
    }

    #[test]
    fn blocks_subdomains() {
        let (set, _) = build(&[], &[(1, "||example.com^")]);
        assert!(is_block(&set.check("example.com")));
        assert!(is_block(&set.check("a.b.example.com")));
        assert_eq!(set.check("notexample.com"), Verdict::Pass);
        assert_eq!(set.check("com"), Verdict::Pass);
    }

    #[test]
    fn verdict_names_the_rule_and_list() {
        let (set, _) = build(&["@@||ok.com^"], &[(7, "||ads.com^")]);
        assert_eq!(
            set.check("x.ads.com"),
            Verdict::Block {
                list_id: 7,
                rule: "||ads.com^".into()
            }
        );
        assert_eq!(
            set.check("ok.com"),
            Verdict::Allow {
                list_id: 0,
                rule: "@@||ok.com^".into()
            }
        );
    }

    #[test]
    fn allow_beats_block() {
        let (set, _) = build(&[], &[(1, "||x.com^\n@@||x.com^")]);
        assert!(matches!(set.check("x.com"), Verdict::Allow { .. }));
        // A more specific block does not override a parent allow, only `important` would.
        let (set, _) = build(&[], &[(1, "||ads.x.com^\n@@||x.com^")]);
        assert!(matches!(set.check("ads.x.com"), Verdict::Allow { .. }));
    }

    #[test]
    fn important_beats_allow() {
        let (set, _) = build(&[], &[(1, "@@||x.com^\n||x.com^$important")]);
        assert!(is_block(&set.check("x.com")));
    }

    #[test]
    fn important_list_rule_beats_plain_user_allow() {
        let (set, _) = build(&["@@||x.com^"], &[(1, "||x.com^$important")]);
        assert!(is_block(&set.check("x.com")));
    }

    #[test]
    fn important_user_allow_beats_everything() {
        let (set, _) = build(&["@@||x.com^$important"], &[(1, "||x.com^$important")]);
        assert_eq!(
            set.check("x.com"),
            Verdict::Allow {
                list_id: 0,
                rule: "@@||x.com^$important".into()
            }
        );
        assert!(matches!(set.check("a.x.com"), Verdict::Allow { .. }));
    }

    #[test]
    fn badfilter_cancels_exact_rule() {
        let (set, _) = build(&[], &[(1, "||x.com^"), (2, "||x.com^$badfilter")]);
        assert_eq!(set.check("x.com"), Verdict::Pass);
        assert_eq!(set.rule_count(), 0);
        // Only the exact twin is cancelled.
        let (set, _) = build(
            &[],
            &[
                (1, "||x.com^$important\n||y.com^"),
                (2, "||x.com^$badfilter"),
            ],
        );
        assert!(is_block(&set.check("x.com")));
        let (set, _) = build(
            &[],
            &[
                (1, "||x.com^$important"),
                (2, "||x.com^$important,badfilter"),
            ],
        );
        assert_eq!(set.check("x.com"), Verdict::Pass);
    }

    #[test]
    fn hosts_ip_matches_exact_name_only_and_loses_to_block() {
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let (set, _) = build(&["10.0.0.9 nas.lan"], &[]);
        assert!(
            matches!(set.check("nas.lan"), Verdict::HostsIp { ip: got, list_id: 0, .. } if got == ip)
        );
        assert_eq!(set.check("a.nas.lan"), Verdict::Pass);
        let (set, _) = build(&["10.0.0.9 nas.lan", "||nas.lan^"], &[]);
        assert!(is_block(&set.check("a.nas.lan")));
        assert!(is_block(&set.check("nas.lan")), "block beats hosts IP");
        let (set, _) = build(&["||evil.com^"], &[(1, "1.2.3.4 evil.com")]);
        assert!(is_block(&set.check("evil.com")));
        let (set, _) = build(&["@@||nas.lan^"], &[(1, "10.0.0.9 nas.lan")]);
        assert!(matches!(set.check("nas.lan"), Verdict::Allow { .. }));
    }

    #[test]
    fn null_ip_hosts_line_blocks_exact_name_only() {
        let (set, _) = build(&[], &[(1, "0.0.0.0 tracker.net")]);
        assert!(is_block(&set.check("tracker.net")));
        assert_eq!(set.check("a.tracker.net"), Verdict::Pass);
    }

    #[test]
    fn important_block_on_parent_beats_child_allow() {
        let (set, _) = build(&[], &[(1, "@@||a.example.com^\n||example.com^$important")]);
        assert!(is_block(&set.check("x.a.example.com")));
    }

    #[test]
    fn important_allow_on_parent_beats_important_block_on_child() {
        let (set, _) = build(&[], &[(1, "@@||x.com^$important\n||ads.x.com^$important")]);
        assert!(matches!(set.check("ads.x.com"), Verdict::Allow { .. }));
    }

    #[test]
    fn list_badfilter_never_cancels_user_rule() {
        let (set, _) = build(&["||x.com^"], &[(1, "||x.com^$badfilter")]);
        assert!(is_block(&set.check("x.com")));
    }

    #[test]
    fn entries_are_compact() {
        assert!(
            std::mem::size_of::<Entry>() <= 16,
            "Entry is {} bytes",
            std::mem::size_of::<Entry>()
        );
    }

    #[test]
    fn matching_ignores_case_and_trailing_dot() {
        let (set, _) = build(&[], &[(1, "||Example.COM^")]);
        assert!(is_block(&set.check("WWW.EXAMPLE.com.")));
        assert!(is_block(&set.check("example.com.")));
        let (set, _) = build(&[], &[(1, "0.0.0.0 example.com")]);
        assert!(is_block(&set.check("example.com.")));
        assert!(is_block(&set.check("EXAMPLE.COM")));
        assert_eq!(set.check("a.example.com"), Verdict::Pass);
    }

    #[test]
    fn user_badfilter_cancels_user_and_list_twins() {
        let (set, _) = build(&["||x.com^", "||x.com^$badfilter"], &[]);
        assert_eq!(set.check("x.com"), Verdict::Pass);
        let (set, _) = build(&["||x.com^$badfilter"], &[(1, "||x.com^")]);
        assert_eq!(set.check("x.com"), Verdict::Pass);
    }

    #[test]
    fn stats_count_skips_by_reason() {
        let body = "||a.com^\n||b.com^\n/ads[0-9]+/\n||c.com^$client=1.2.3.4\n! note\n";
        let (set, stats) = build(&[], &[(5, body)]);
        let st = stats.iter().find(|s| s.list_id == 5).unwrap();
        assert_eq!(st.parsed, 2);
        let want: BTreeMap<String, usize> =
            [("regex".to_string(), 1), ("modifier:client".to_string(), 1)].into();
        assert_eq!(st.skipped, want);
        assert_eq!(set.rule_count(), 2);
        assert_eq!(stats[0].list_id, 0, "user rules report as list 0");
    }

    /// Reads the reference list live; run with `-- --ignored live_adguard_dns_filter_counts`.
    #[tokio::test]
    #[ignore]
    async fn live_adguard_dns_filter_counts() {
        let url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";
        let body = crate::dns::upstream::client_builder()
            .build()
            .expect("client")
            .get(url)
            .send()
            .await
            .expect("fetch filter_1.txt")
            .text()
            .await
            .expect("body");
        let (set, stats) = RuleSet::build(&[], &[(1, &body)]);
        let st = &stats[1];
        println!(
            "parsed={} indexed={} skipped={:?}",
            st.parsed,
            set.rule_count(),
            st.skipped
        );
        println!(
            "size_of Entry={} est_bytes={}",
            std::mem::size_of::<Entry>(),
            set.estimated_bytes()
        );
        assert!(st.parsed > 10_000);
    }
}
