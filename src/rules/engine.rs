//! The rule set: every list's rules in one map, queried by walking a name's suffixes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use super::{parse_line, Parsed, Rule, RuleKind};

/// What the rules say about one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Block { list_id: u32, rule: Arc<str> },
    Allow { list_id: u32, rule: Arc<str> },
    HostsIp { ip: IpAddr, list_id: u32, rule: Arc<str> },
}

/// Per-list parse outcome, for the list manager to store and show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListStats {
    pub list_id: u32,
    pub parsed: usize,
    /// Keyed by `SkipReason::label()`.
    pub skipped: BTreeMap<String, usize>,
}

/// Where a rule came from and its text; cloning is a refcount bump.
#[derive(Debug, Clone)]
struct Origin {
    list_id: u32,
    rule: Arc<str>,
}

/// The strongest rule of each class for one exact domain (first loaded wins a tie).
#[derive(Debug, Default)]
struct Entry {
    important_allow: Option<Origin>,
    important_block: Option<Origin>,
    allow: Option<Origin>,
    hosts: Option<(IpAddr, Origin)>,
    block: Option<Origin>,
}

impl Entry {
    fn insert(&mut self, list_id: u32, rule: Rule) {
        let origin = Origin { list_id, rule: Arc::from(rule.text) };
        let slot = match (&rule.kind, rule.important) {
            (RuleKind::Allow, true) => &mut self.important_allow,
            (RuleKind::Block, true) => &mut self.important_block,
            (RuleKind::Allow, false) => &mut self.allow,
            (RuleKind::Block, false) => &mut self.block,
            (RuleKind::HostsIp(ip), _) => {
                self.hosts.get_or_insert((*ip, origin));
                return;
            }
        };
        slot.get_or_insert(origin);
    }
}

/// Immutable once built; share it as `Arc<RuleSet>` and swap the Arc to reload.
#[derive(Debug, Default)]
pub struct RuleSet {
    by_domain: HashMap<Box<str>, Entry>,
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

impl RuleSet {
    /// User rules are list 0 and load first, so they win ties against lists.
    pub fn build(user_rules: &[String], lists: &[(u32, &str)]) -> (RuleSet, Vec<ListStats>) {
        let mut stats = Vec::new();
        let mut rules: Vec<(u32, Rule)> = Vec::new();
        let sources = std::iter::once((0, user_rules.join("\n"))).chain(lists.iter().map(|(id, body)| (*id, body.to_string())));
        for (list_id, body) in sources {
            let mut st = ListStats { list_id, parsed: 0, skipped: BTreeMap::new() };
            for line in body.lines() {
                match parse_line(line) {
                    Parsed::Rule(rule) => {
                        st.parsed += 1;
                        rules.push((list_id, rule));
                    }
                    Parsed::Skip(reason) => *st.skipped.entry(reason.label()).or_insert(0) += 1,
                    Parsed::Blank => {}
                }
            }
            stats.push(st);
        }

        // Badfilter applies across lists, so it can only run once every list is read.
        let cancelled: HashSet<String> = rules.iter().filter(|(_, r)| r.badfilter).map(|(_, r)| badfilter_twin(&r.text)).collect();
        let mut set = RuleSet::default();
        for (list_id, rule) in rules {
            if rule.badfilter || cancelled.contains(&rule.text) {
                continue;
            }
            set.count += 1;
            set.by_domain.entry(rule.domain.clone().into_boxed_str()).or_default().insert(list_id, rule);
        }
        (set, stats)
    }

    pub fn rule_count(&self) -> usize {
        self.count
    }

    /// Precedence (uBO/AdGuard): important allow, important block, allow, hosts IP, block.
    /// A rule for `example.com` covers every subdomain, so each suffix of the name is looked up.
    pub fn check(&self, name: &str) -> Verdict {
        // The one allocation: ASCII lowercase of the name, minus a trailing dot.
        let lowered = name.to_ascii_lowercase();
        let mut suffix = lowered.strip_suffix('.').unwrap_or(&lowered);

        let (mut imp_block, mut allow, mut hosts, mut block): (Option<&Origin>, Option<&Origin>, Option<&(IpAddr, Origin)>, Option<&Origin>) =
            (None, None, None, None);
        loop {
            if let Some(entry) = self.by_domain.get(suffix) {
                if let Some(o) = &entry.important_allow {
                    return Verdict::Allow { list_id: o.list_id, rule: o.rule.clone() };
                }
                // The most specific suffix to hit a class wins that class.
                imp_block = imp_block.or(entry.important_block.as_ref());
                allow = allow.or(entry.allow.as_ref());
                hosts = hosts.or(entry.hosts.as_ref());
                block = block.or(entry.block.as_ref());
            }
            match suffix.split_once('.') {
                Some((_, parent)) => suffix = parent,
                None => break,
            }
        }

        if let Some(o) = imp_block {
            Verdict::Block { list_id: o.list_id, rule: o.rule.clone() }
        } else if let Some(o) = allow {
            Verdict::Allow { list_id: o.list_id, rule: o.rule.clone() }
        } else if let Some((ip, o)) = hosts {
            Verdict::HostsIp { ip: *ip, list_id: o.list_id, rule: o.rule.clone() }
        } else if let Some(o) = block {
            Verdict::Block { list_id: o.list_id, rule: o.rule.clone() }
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
        assert_eq!(set.check("x.ads.com"), Verdict::Block { list_id: 7, rule: "||ads.com^".into() });
        assert_eq!(set.check("ok.com"), Verdict::Allow { list_id: 0, rule: "@@||ok.com^".into() });
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
        assert_eq!(set.check("x.com"), Verdict::Allow { list_id: 0, rule: "@@||x.com^$important".into() });
        assert!(matches!(set.check("a.x.com"), Verdict::Allow { .. }));
    }

    #[test]
    fn badfilter_cancels_exact_rule() {
        let (set, _) = build(&[], &[(1, "||x.com^"), (2, "||x.com^$badfilter")]);
        assert_eq!(set.check("x.com"), Verdict::Pass);
        assert_eq!(set.rule_count(), 0);
        // Only the exact twin is cancelled.
        let (set, _) = build(&[], &[(1, "||x.com^$important\n||y.com^"), (2, "||x.com^$badfilter")]);
        assert!(is_block(&set.check("x.com")));
        let (set, _) = build(&[], &[(1, "||x.com^$important"), (2, "||x.com^$important,badfilter")]);
        assert_eq!(set.check("x.com"), Verdict::Pass);
    }

    #[test]
    fn hosts_ip_sits_between_allow_and_block() {
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let (set, _) = build(&[], &[(1, "10.0.0.9 nas.lan\n||nas.lan^")]);
        assert!(matches!(set.check("nas.lan"), Verdict::HostsIp { ip: got, list_id: 1, .. } if got == ip));
        let (set, _) = build(&["@@||nas.lan^"], &[(1, "10.0.0.9 nas.lan")]);
        assert!(matches!(set.check("nas.lan"), Verdict::Allow { .. }));
    }

    #[test]
    fn matching_ignores_case_and_trailing_dot() {
        let (set, _) = build(&[], &[(1, "||Example.COM^")]);
        assert!(is_block(&set.check("WWW.EXAMPLE.com.")));
        assert!(is_block(&set.check("example.com.")));
    }

    #[test]
    fn stats_count_skips_by_reason() {
        let body = "||a.com^\n||b.com^\n/ads[0-9]+/\n||c.com^$client=1.2.3.4\n! note\n";
        let (set, stats) = build(&[], &[(5, body)]);
        let st = stats.iter().find(|s| s.list_id == 5).unwrap();
        assert_eq!(st.parsed, 2);
        let want: BTreeMap<String, usize> = [("regex".to_string(), 1), ("modifier:client".to_string(), 1)].into();
        assert_eq!(st.skipped, want);
        assert_eq!(set.rule_count(), 2);
        assert_eq!(stats[0].list_id, 0, "user rules report as list 0");
    }

    /// Reads the reference list live; run with `-- --ignored live_adguard_dns_filter_counts`.
    #[test]
    #[ignore]
    fn live_adguard_dns_filter_counts() {
        let url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";
        let body = reqwest::blocking::get(url).and_then(|r| r.text()).expect("fetch filter_1.txt");
        let (set, stats) = RuleSet::build(&[], &[(1, &body)]);
        let st = &stats[1];
        println!("parsed={} indexed={} skipped={:?}", st.parsed, set.rule_count(), st.skipped);
        assert!(st.parsed > 10_000);
    }
}
