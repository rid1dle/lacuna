//! The rule set: every list's rules in one map, queried by walking a name's suffixes, plus a
//! small pattern table for the rules a suffix lookup cannot express.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use super::pattern::PatternTable;
use super::{parse_line, Parsed, Rule, RuleKind, Target};

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

/// The four precedence classes of block and allow rules, strongest first.
#[derive(Debug, Clone, Copy)]
enum Class {
    ImportantAllow,
    ImportantBlock,
    Allow,
    Block,
}

impl Class {
    /// None for hosts IPs: they live in `RuleSet::hosts_ip`, below every class.
    fn of(kind: &RuleKind, important: bool) -> Option<Class> {
        match (kind, important) {
            (RuleKind::Allow, true) => Some(Class::ImportantAllow),
            (RuleKind::Block, true) => Some(Class::ImportantBlock),
            (RuleKind::Allow, false) => Some(Class::Allow),
            (RuleKind::Block, false) => Some(Class::Block),
            (RuleKind::HostsIp(_), _) => None,
        }
    }
}

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
    /// Indices grow in load order, so the smallest is the first loaded (user rules first).
    fn keep_first(&mut self, class: Class, index: NonZeroU32) {
        let slot = match class {
            Class::ImportantAllow => &mut self.important_allow,
            Class::ImportantBlock => &mut self.important_block,
            Class::Allow => &mut self.allow,
            Class::Block => &mut self.block,
        };
        *slot = Some(slot.map_or(index, |old| old.min(index)));
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
    /// Wildcards, `|` anchors and unanchored text: a few hundred, compiled once here.
    patterns: PatternTable<(Class, NonZeroU32)>,
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
                target,
                kind,
                important,
                badfilter,
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
            let class = Class::of(&kind, important);
            match (target, kind, class) {
                (Target::Exact(name), RuleKind::HostsIp(ip), _) => {
                    set.hosts_ip
                        .entry(name.into_boxed_str())
                        .or_insert((ip, index));
                }
                // The parser makes exact targets only for hosts lines, so this is a block.
                (Target::Exact(name), _, _) => {
                    set.exact_block
                        .entry(name.into_boxed_str())
                        .or_insert(index);
                }
                (Target::Suffix(domain), _, Some(class)) => set
                    .suffix
                    .entry(domain.into_boxed_str())
                    .or_default()
                    .keep_first(class, index),
                (Target::Pattern(pattern), _, Some(class)) => {
                    set.patterns.insert(pattern, (class, index));
                }
                // No class means a hosts IP, and the parser gives those exact targets only.
                (Target::Suffix(_) | Target::Pattern(_), _, None) => {}
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
            + self.patterns.estimated_bytes()
    }

    fn verdict(&self, index: NonZeroU32, make: impl FnOnce(u32, Arc<str>) -> Verdict) -> Verdict {
        // Indices are only ever handed out by `build`, so the lookup cannot miss.
        match self.origins.get(index.get() as usize - 1) {
            Some(o) => make(o.list_id, o.rule.clone()),
            None => Verdict::Pass,
        }
    }

    /// Precedence (AdGuard): important allow, important block, allow, block, hosts IP.
    /// `||example.com^` covers every subdomain, so each suffix of the name is looked up;
    /// hosts lines and lines that are only a host name match the exact name. Pattern rules
    /// join the same classes; within a class a suffix hit is reported before a pattern hit.
    pub fn check(&self, name: &str) -> Verdict {
        // The one allocation: ASCII lowercase of the name, minus a trailing dot.
        let lowered = name.to_ascii_lowercase();
        let full = lowered.strip_suffix('.').unwrap_or(&lowered);

        let mut hit = Entry::default();
        let mut suffix = full;
        loop {
            if let Some(entry) = self.suffix.get(suffix) {
                if let Some(i) = entry.important_allow {
                    return self.verdict(i, |list_id, rule| Verdict::Allow { list_id, rule });
                }
                // The most specific suffix to hit a class wins that class.
                hit.important_block = hit.important_block.or(entry.important_block);
                hit.allow = hit.allow.or(entry.allow);
                hit.block = hit.block.or(entry.block);
            }
            match suffix.split_once('.') {
                Some((_, parent)) => suffix = parent,
                None => break,
            }
        }
        hit.block = hit.block.or_else(|| self.exact_block.get(full).copied());

        let mut by_pattern = Entry::default();
        self.patterns
            .for_each_match(full, |&(class, i)| by_pattern.keep_first(class, i));
        let imp_allow = by_pattern.important_allow;
        let imp_block = hit.important_block.or(by_pattern.important_block);
        let allow = hit.allow.or(by_pattern.allow);
        let block = hit.block.or(by_pattern.block);

        if let Some(i) = imp_allow {
            self.verdict(i, |list_id, rule| Verdict::Allow { list_id, rule })
        } else if let Some(i) = imp_block {
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

    fn is_allow(v: &Verdict) -> bool {
        matches!(v, Verdict::Allow { .. })
    }

    // The rule texts below are real lines from the AdGuard DNS filter that the shadow
    // compare found lacuna skipping.

    #[test]
    fn wildcard_at_host_start() {
        let (set, _) = build(&[], &[(1, "||*cdn-settings.appsflyersdk.com^")]);
        assert_eq!(
            set.check("kz4tx3-cdn-settings.appsflyersdk.com"),
            Verdict::Block {
                list_id: 1,
                rule: "||*cdn-settings.appsflyersdk.com^".into()
            }
        );
        assert!(is_block(&set.check("9m71lc.cdn-settings.appsflyersdk.com")));
        assert_eq!(
            set.check("cdn-settings.appsflyersdk.com.evil"),
            Verdict::Pass
        );
    }

    #[test]
    fn wildcard_as_tld() {
        let (set, _) = build(&[], &[(1, "||aan.amazon.*^")]);
        assert!(is_block(&set.check("aan.amazon.in")));
        assert!(is_block(&set.check("x.aan.amazon.co.uk")));
        assert_eq!(set.check("xaan.amazon.in"), Verdict::Pass);
    }

    #[test]
    fn wildcard_mid_name() {
        let (set, _) = build(&[], &[(1, "||mobileanalytics.*.amazonaws.com^")]);
        assert!(is_block(
            &set.check("mobileanalytics.us-east-1.amazonaws.com")
        ));
        assert_eq!(set.check("mobileanalytics.amazonaws.com"), Verdict::Pass);
        let (set, _) = build(&[], &[(1, "||sdk-*.moengage.com^")]);
        assert!(is_block(&set.check("sdk-01.moengage.com")));
        assert_eq!(set.check("moengage.com"), Verdict::Pass);
    }

    #[test]
    fn leading_dot_needs_a_label_before_it() {
        let (set, _) = build(&[], &[(1, ".skadsdkless.appsflyersdk.com^")]);
        assert!(is_block(&set.check("neqm8i.skadsdkless.appsflyersdk.com")));
        assert_eq!(set.check("skadsdkless.appsflyersdk.com"), Verdict::Pass);
    }

    #[test]
    fn domain_anchor_with_trailing_pipe_allows() {
        let (set, _) = build(
            &[],
            &[(1, "||googleadservices.com^\n@@||www.googleadservices.com^|")],
        );
        assert_eq!(
            set.check("www.googleadservices.com"),
            Verdict::Allow {
                list_id: 1,
                rule: "@@||www.googleadservices.com^|".into()
            }
        );
        assert!(is_block(&set.check("googleadservices.com")));
    }

    #[test]
    fn start_anchor_allows_the_exact_name_only() {
        let (set, _) = build(&[], &[(1, "||taboola.com^\n@@|cdn.taboola.com^|")]);
        assert!(is_allow(&set.check("cdn.taboola.com")));
        assert!(is_block(&set.check("x.cdn.taboola.com")));
    }

    #[test]
    fn wildcard_rules_share_precedence() {
        let (set, _) = build(&[], &[(1, "||*ads.example^$important\n@@||x.ads.example^")]);
        assert!(is_block(&set.check("x.ads.example")));
        let (set, _) = build(&[], &[(1, "@@||*.cdn.example^\n||x.cdn.example^")]);
        assert!(is_allow(&set.check("x.cdn.example")));
        // An important allow pattern beats an important suffix block.
        let (set, _) = build(
            &[],
            &[(1, "||cdn.example^$important\n@@|*.cdn.example^$important")],
        );
        assert!(is_allow(&set.check("x.cdn.example")));
        assert!(is_block(&set.check("cdn.example")));
    }

    #[test]
    fn domain_anchor_without_separator_is_a_prefix() {
        // `||an.yandex.` is a label run followed by anything, not the name `an.yandex`.
        let (set, _) = build(&[], &[(1, "||an.yandex.")]);
        assert!(is_block(&set.check("an.yandex.ru")));
        assert!(is_block(&set.check("x.an.yandex.com")));
        assert_eq!(set.check("an.yandex"), Verdict::Pass);
        assert_eq!(set.check("xan.yandex.ru"), Verdict::Pass);
        let (set, _) = build(&[], &[(1, "||direct-specific.com")]);
        assert!(is_block(&set.check("direct-specific.com")));
        assert!(is_block(&set.check("a.direct-specific.com.au")));
        assert_eq!(set.check("notdirect-specific.com"), Verdict::Pass);
    }

    #[test]
    fn unanchored_line_matches_anywhere() {
        let (set, _) = build(&[], &[(1, "-ads1.\n-ad123-")]);
        assert!(is_block(&set.check("foo-ads1.example.com")));
        assert!(is_block(&set.check("x-ad123-y.example.com")));
        assert_eq!(set.check("ads1.example.com"), Verdict::Pass);
    }

    #[test]
    fn plain_domain_line_is_the_exact_name() {
        let (set, _) = build(&[], &[(1, "plain.example.org")]);
        assert!(is_block(&set.check("plain.example.org")));
        assert_eq!(set.check("a.plain.example.org"), Verdict::Pass);
        // An allow has no hosts form, so the same text is a substring pattern.
        let (set, _) = build(&[], &[(1, "||example.org^\n@@plain.example.org")]);
        assert!(is_allow(&set.check("a.plain.example.org")));
    }

    #[test]
    fn badfilter_cancels_a_wildcard_twin() {
        let (set, _) = build(
            &[],
            &[
                (1, "||sdk-*.moengage.com^"),
                (2, "||sdk-*.moengage.com^$badfilter"),
            ],
        );
        assert_eq!(set.check("sdk-01.moengage.com"), Verdict::Pass);
        assert_eq!(set.rule_count(), 0);
        let (set, _) = build(
            &["||sdk-*.moengage.com^"],
            &[(1, "||sdk-*.moengage.com^$badfilter")],
        );
        assert!(is_block(&set.check("sdk-01.moengage.com")), "R11");
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
        let rss_before = rss_kib();
        let (set, stats) = RuleSet::build(&[], &[(1, &body)]);
        let rss_after = rss_kib();
        let st = &stats[1];
        println!(
            "parsed={} indexed={} patterns={} skipped={:?}",
            st.parsed,
            set.rule_count(),
            set.patterns.len(),
            st.skipped
        );
        println!(
            "size_of Entry={} est_bytes={} pattern_est_bytes={} rss_delta_kib={}",
            std::mem::size_of::<Entry>(),
            set.estimated_bytes(),
            set.patterns.estimated_bytes(),
            rss_after.saturating_sub(rss_before)
        );
        assert!(st.parsed > 10_000);
        assert_eq!(st.skipped.get("wildcard"), None);

        // Names from the shadow compare, against the real list.
        assert!(is_block(&set.check("kz4tx3-cdn-settings.appsflyersdk.com")));
        assert!(is_block(&set.check("neqm8i.skadsdkless.appsflyersdk.com")));
        assert!(is_allow(&set.check("www.googleadservices.com")));
        assert!(is_allow(&set.check("cdn.taboola.com")));

        let names = [
            "www.google.com",
            "i.ytimg.com",
            "graph.facebook.com",
            "kz4tx3-cdn-settings.appsflyersdk.com",
            "mobileanalytics.us-east-1.amazonaws.com",
            "a-long-subdomain-name.cdn.example-cloud.net",
        ];
        let rounds = 20_000;
        let start = std::time::Instant::now();
        for _ in 0..rounds {
            for name in names {
                std::hint::black_box(set.check(std::hint::black_box(name)));
            }
        }
        let per = start.elapsed().as_nanos() / (rounds * names.len()) as u128;
        println!("check: {per} ns per name (mean over {} names)", names.len());
    }

    /// Resident set size of this process, from /proc (Linux only).
    fn rss_kib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("VmRSS:"))
                    .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            })
            .unwrap_or(0)
    }
}
