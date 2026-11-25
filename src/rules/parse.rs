//! One line of a uBlock/AdGuard filter list, DNS subset.

use std::net::IpAddr;

use super::pattern::Pattern;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Rule(Rule),
    /// A real rule we deliberately do not support; counted, not an error.
    Skip(SkipReason),
    /// Comments, empty lines and hosts-file boilerplate.
    Blank,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub target: Target,
    pub kind: RuleKind,
    pub important: bool,
    pub badfilter: bool,
    /// The original line, trimmed.
    pub text: String,
}

/// Which names a rule covers. Names are lowercase with no trailing dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `||domain^`: the name and every subdomain.
    Suffix(String),
    /// Hosts lines and lines that are only a host name: this exact name.
    Exact(String),
    /// Any other pattern (wildcards, `|` anchors, unanchored text), matched as AdGuard does.
    Pattern(Pattern),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleKind {
    Block,
    Allow,
    /// A hosts line with a non-null IP: answer with that address.
    HostsIp(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    Regex,
    /// Name of the unsupported `$` modifier.
    Modifier(String),
    UrlPath,
    Invalid,
}

/// AdGuard/uBO modifiers worth counting by name.
const KNOWN_MODIFIERS: [&str; 13] = [
    "client",
    "dnstype",
    "denyallow",
    "dnsrewrite",
    "ctag",
    "third-party",
    "domain",
    "script",
    "image",
    "popup",
    "document",
    "all",
    "match-case",
];

impl SkipReason {
    /// Stable key for skip counters.
    pub fn label(&self) -> String {
        match self {
            SkipReason::Regex => "regex".into(),
            SkipReason::Modifier(name) => {
                // Names come from list text, so only known ones may become a counter key.
                let lower = name.to_ascii_lowercase();
                if KNOWN_MODIFIERS.contains(&lower.as_str()) {
                    format!("modifier:{lower}")
                } else {
                    "modifier:other".into()
                }
            }
            SkipReason::UrlPath => "url_path".into(),
            SkipReason::Invalid => "invalid".into(),
        }
    }
}

/// Names a hosts file lists for the machine itself; they are not ad rules.
fn is_hosts_boilerplate(name: &str) -> bool {
    matches!(
        name,
        "localhost" | "localhost.localdomain" | "broadcasthost" | "local"
    ) || name.starts_with("ip6-")
}

pub fn parse_line(line: &str) -> Parsed {
    let text = line.trim();
    if text.is_empty() || text.starts_with('!') || text.starts_with('#') {
        return Parsed::Blank;
    }

    // A hosts line is "<ip> <name>", so it has whitespace; filter rules never do.
    if text.contains(char::is_whitespace) {
        return parse_hosts(text);
    }

    let (allow, rest) = match text.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, text),
    };

    // A regex rule is /.../ and may itself contain `$`, so test it before splitting modifiers.
    if rest.len() > 1 && rest.starts_with('/') && rest.ends_with('/') {
        return Parsed::Skip(SkipReason::Regex);
    }
    // `/re$x/$important`: the regex ends at the last `/` that opens the modifiers.
    if rest.starts_with('/') && rest.rfind("/$").is_some_and(|i| i > 0) {
        return Parsed::Skip(SkipReason::Regex);
    }

    // Classify by the part before the first `$`: a `$` can sit inside a URL query or a regex.
    let (pattern, modifiers) = match rest.split_once('$') {
        Some((pattern, mods)) => (pattern, Some(mods)),
        None => (rest, None),
    };
    if pattern.len() > 1 && pattern.starts_with('/') && pattern.ends_with('/') {
        return Parsed::Skip(SkipReason::Regex);
    }
    let after_scheme = pattern.strip_prefix("://");
    if after_scheme.unwrap_or(pattern).contains('/') {
        return Parsed::Skip(SkipReason::UrlPath);
    }

    let (mut important, mut badfilter) = (false, false);
    if let Some(mods) = modifiers {
        for modifier in mods.split(',') {
            // `client=1.2.3.4` has a value; only the name decides support.
            let name = modifier.split_once('=').map_or(modifier, |(name, _)| name);
            match name {
                "important" => important = true,
                "badfilter" => badfilter = true,
                "" => return Parsed::Skip(SkipReason::Invalid),
                other => return Parsed::Skip(SkipReason::Modifier(other.to_string())),
            }
        }
    }

    let target = if let Some(rest) = after_scheme {
        match Pattern::parse_after_scheme(rest) {
            Some(p) => Target::Pattern(p),
            None => return Parsed::Skip(SkipReason::Invalid),
        }
    } else if !allow && modifiers.is_none() && is_host_rule_name(pattern) {
        // AdGuard reads a line that is only a host name as a hosts line for 0.0.0.0, which
        // blocks that exact name (urlfilter `rules/rule.go` `NewRule` tries `NewHostRule`
        // first; `dnsengine.go` looks host rules up by the exact hostname).
        Target::Exact(pattern.to_ascii_lowercase())
    } else if let Some(domain) = suffix_shape(pattern) {
        // AdGuard matches the dot literally and a hostname never ends in one, so
        // `||example.com.^` can never match: count it rather than widen it.
        if domain.ends_with('.') {
            return Parsed::Skip(SkipReason::Invalid);
        }
        match normalize_domain(domain) {
            Some(domain) => Target::Suffix(domain),
            None => return Parsed::Skip(SkipReason::Invalid),
        }
    } else {
        match Pattern::parse(pattern) {
            Some(p) => Target::Pattern(p),
            None => return Parsed::Skip(SkipReason::Invalid),
        }
    };

    Parsed::Rule(Rule {
        target,
        kind: if allow {
            RuleKind::Allow
        } else {
            RuleKind::Block
        },
        important,
        badfilter,
        text: text.to_string(),
    })
}

/// The `domain` of `||domain^`, `||domain^|` or `||domain|`, the forms the suffix table
/// holds. In a hostname nothing can follow `^`, so all three mean "the name or a
/// subdomain"; `||domain` with neither is a prefix (`||ads.` matches `ads.example.com`) and
/// goes to the pattern matcher instead.
fn suffix_shape(pattern: &str) -> Option<&str> {
    let body = pattern.strip_prefix("||")?;
    let domain = body
        .strip_suffix("^|")
        .or_else(|| body.strip_suffix('^'))
        .or_else(|| body.strip_suffix('|'))?;
    (!domain.contains(['*', '^', '|'])).then_some(domain)
}

/// urlfilter's `ufnet.IsDomainName`, which decides whether a bare line is a host rule:
/// labels of letters, digits and inner hyphens, `xn--` labels at least 8 long, and a last
/// label of 2 or more characters that starts and ends with a letter.
fn is_host_rule_name(name: &str) -> bool {
    fn label_ok(label: &str) -> bool {
        let b = label.as_bytes();
        !b.is_empty()
            && b.len() <= 63
            && (!label.starts_with("xn--") || b.len() >= 8)
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
    }
    // `rsplit` always yields at least one piece.
    let tld = name.rsplit('.').next().unwrap_or(name).as_bytes();
    name.len() <= 253
        && name.split('.').all(label_ok)
        && tld.len() >= 2
        && tld[0].is_ascii_alphabetic()
        && tld[tld.len() - 1].is_ascii_alphabetic()
}

fn parse_hosts(text: &str) -> Parsed {
    // Hosts files allow a trailing "# comment".
    let body = text.split('#').next().unwrap_or(text);
    let mut tokens = body.split_whitespace();
    let (Some(addr), Some(name)) = (tokens.next(), tokens.next()) else {
        return Parsed::Skip(SkipReason::Invalid);
    };
    let extra: Vec<&str> = tokens.collect();
    // A line naming only the machine itself (`127.0.0.1 localhost localhost.localdomain`) is boilerplate.
    if std::iter::once(name)
        .chain(extra.iter().copied())
        .all(|n| is_hosts_boilerplate(&n.to_ascii_lowercase()))
    {
        return Parsed::Blank;
    }
    if !extra.is_empty() {
        return Parsed::Skip(SkipReason::Invalid);
    }
    let (Ok(ip), Some(domain)) = (addr.parse::<IpAddr>(), normalize_domain(name)) else {
        return Parsed::Skip(SkipReason::Invalid);
    };
    Parsed::Rule(Rule {
        target: Target::Exact(domain),
        kind: if ip.is_unspecified() || ip.is_loopback() {
            RuleKind::Block
        } else {
            RuleKind::HostsIp(ip)
        },
        important: false,
        badfilter: false,
        text: text.to_string(),
    })
}

/// Lowercase, drop one trailing dot, and accept only `a-z0-9-_.` with non-empty labels.
/// Punycode (`xn--`) is plain ASCII, so it passes; raw Unicode does not.
fn normalize_domain(raw: &str) -> Option<String> {
    let name = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 253
        && name
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'));
    valid.then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(line: &str) -> Rule {
        match parse_line(line) {
            Parsed::Rule(r) => r,
            other => panic!("{line:?} parsed as {other:?}"),
        }
    }

    fn skip(line: &str) -> SkipReason {
        match parse_line(line) {
            Parsed::Skip(s) => s,
            other => panic!("{line:?} parsed as {other:?}"),
        }
    }

    #[test]
    fn domain_anchor_blocks() {
        let r = rule("||ads.example.com^");
        assert_eq!(r.target, Target::Suffix("ads.example.com".into()));
        assert_eq!(r.kind, RuleKind::Block);
        assert!(!r.important);
        assert!(!r.badfilter);
        assert_eq!(r.text, "||ads.example.com^");
    }

    #[test]
    fn exception_allows() {
        let r = rule("@@||ok.example.com^");
        assert_eq!(r.target, Target::Suffix("ok.example.com".into()));
        assert_eq!(r.kind, RuleKind::Allow);
    }

    #[test]
    fn supported_modifiers() {
        assert!(rule("||x.com^$important").important);
        assert!(rule("||x.com^$badfilter").badfilter);
        let r = rule("@@||x.com^$important,badfilter");
        assert!(r.important && r.badfilter);
        assert_eq!(r.kind, RuleKind::Allow);
    }

    #[test]
    fn hosts_lines() {
        assert_eq!(rule("0.0.0.0 tracker.net").kind, RuleKind::Block);
        assert_eq!(rule("127.0.0.1 tracker.net").kind, RuleKind::Block);
        assert_eq!(rule("::1 tracker.net").kind, RuleKind::Block);
        assert_eq!(
            rule("0.0.0.0\ttracker.net # trailing").target,
            Target::Exact("tracker.net".into())
        );
        let r = rule("10.1.2.3 intranet.example");
        assert_eq!(r.kind, RuleKind::HostsIp("10.1.2.3".parse().unwrap()));
        assert_eq!(r.target, Target::Exact("intranet.example".into()));
        assert_eq!(skip("0.0.0.0 a.com b.com"), SkipReason::Invalid);
    }

    #[test]
    fn hosts_boilerplate_is_blank() {
        for line in [
            "127.0.0.1 localhost",
            "127.0.0.1 localhost.localdomain",
            "255.255.255.255 broadcasthost",
            "0.0.0.0 local",
            "::1 ip6-localhost",
            "fe00::0 ip6-localnet",
            "fe80::1%lo0 localhost",
        ] {
            assert_eq!(parse_line(line), Parsed::Blank, "{line}");
        }
    }

    #[test]
    fn host_name_line_is_an_exact_block() {
        let r = rule("Plain.Example.org");
        assert_eq!(r.target, Target::Exact("plain.example.org".into()));
        assert_eq!(r.kind, RuleKind::Block);
        // Not a host name by urlfilter's rules, so an unanchored pattern: a leading
        // hyphen, a trailing dot, a TLD ending in a digit, a short `xn--` label.
        for line in ["-ad123-", "adserver.", "ads.example.c0", "xn--a.com"] {
            assert!(matches!(rule(line).target, Target::Pattern(_)), "{line}");
        }
        // An allow or a modifier has no hosts form either.
        assert!(matches!(
            rule("@@plain.example.org").target,
            Target::Pattern(_)
        ));
        assert!(matches!(
            rule("plain.example.org$important").target,
            Target::Pattern(_)
        ));
    }

    #[test]
    fn suffix_shapes_and_patterns() {
        for line in ["||x.com^", "||x.com^|", "||x.com|", "@@||x.com^|"] {
            assert_eq!(rule(line).target, Target::Suffix("x.com".into()), "{line}");
        }
        for line in [
            "||*cdn-settings.appsflyersdk.com^",
            "||aan.amazon.*^",
            "||sdk-*.moengage.com^",
            ".skadsdkless.appsflyersdk.com^",
            "@@|cdn.taboola.com^|",
            "||an.yandex.",
            "||direct-specific.com",
            "w.example.com^",
        ] {
            assert!(matches!(rule(line).target, Target::Pattern(_)), "{line}");
        }
        let r = rule("@@||*.cdn.example^$important");
        assert!(r.important && r.kind == RuleKind::Allow);
    }

    #[test]
    fn comments_and_empty_are_blank() {
        assert_eq!(parse_line("! comment"), Parsed::Blank);
        assert_eq!(parse_line("# comment"), Parsed::Blank);
        assert_eq!(parse_line(""), Parsed::Blank);
        assert_eq!(parse_line("   \t"), Parsed::Blank);
    }

    #[test]
    fn regex_skipped() {
        assert_eq!(skip("/ads[0-9]+\\.com/"), SkipReason::Regex);
        assert_eq!(skip("@@/ads[0-9]+\\.com/"), SkipReason::Regex);
    }

    #[test]
    fn unsupported_modifiers_skipped() {
        for name in ["client", "dnstype", "denyallow", "dnsrewrite", "ctag"] {
            let line = format!("||x.com^${name}=192.168.0.5");
            assert_eq!(skip(&line), SkipReason::Modifier(name.into()), "{line}");
        }
        // One unsupported modifier poisons the rule even beside a supported one.
        assert_eq!(
            skip("||x.com^$important,client=1.2.3.4"),
            SkipReason::Modifier("client".into())
        );
    }

    #[test]
    fn url_path_skipped() {
        assert_eq!(skip("||example.com/ads/"), SkipReason::UrlPath);
        assert_eq!(skip("://ads.example.com/x^"), SkipReason::UrlPath);
        assert_eq!(skip("http://ads.example.com^"), SkipReason::UrlPath);
    }

    #[test]
    fn scheme_separator_rules_are_patterns() {
        for line in ["://jhf.ru^", "://*.a-akamaihd.com^", "://sportframe*.co^"] {
            assert!(matches!(rule(line).target, Target::Pattern(_)), "{line}");
        }
    }

    #[test]
    fn normalizes_case_and_skips_trailing_dot() {
        assert_eq!(
            rule("||EXAMPLE.Com^").target,
            Target::Suffix("example.com".into())
        );
        // AdGuard matches `example.com.` literally, and a hostname never ends in a dot.
        assert_eq!(skip("||example.com.^"), SkipReason::Invalid);
        assert_eq!(skip("@@||example.com.^|"), SkipReason::Invalid);
    }

    #[test]
    fn invalid_shapes() {
        for line in [
            "||^",
            "||.example.com^",
            "||a..b^",
            "||exa mple.com^",
            "||bücher.de^",
            "||x.com^$",
            "garbage line here",
            "||*^",
            "a|b.com^",
            "a^",
        ] {
            assert_eq!(skip(line), SkipReason::Invalid, "{line}");
        }
        assert!(matches!(parse_line("||xn--bcher-kva.de^"), Parsed::Rule(_)));
        assert!(matches!(parse_line("||a_b.c-d.com^"), Parsed::Rule(_)));
    }

    #[test]
    fn classification_order_url_and_regex_before_modifiers() {
        assert_eq!(skip("||example.com/p?a=$b"), SkipReason::UrlPath);
        assert_eq!(skip("/re/$important"), SkipReason::Regex);
        assert_eq!(skip("@@/ads[0-9]+/$important"), SkipReason::Regex);
    }

    #[test]
    fn multi_name_boilerplate_hosts_lines_are_blank() {
        assert_eq!(
            parse_line("127.0.0.1 localhost localhost.localdomain"),
            Parsed::Blank
        );
        assert_eq!(
            parse_line("::1 localhost ip6-localhost ip6-loopback"),
            Parsed::Blank
        );
        assert_eq!(skip("0.0.0.0 localhost a.com"), SkipReason::Invalid);
    }

    #[test]
    fn regex_with_dollar_inside_is_regex() {
        assert_eq!(skip("/a$b/$important"), SkipReason::Regex);
    }

    #[test]
    fn hosts_lines_are_exact_and_adblock_rules_are_not() {
        assert!(matches!(
            rule("0.0.0.0 tracker.net").target,
            Target::Exact(_)
        ));
        assert!(matches!(
            rule("10.1.2.3 intranet.example").target,
            Target::Exact(_)
        ));
        assert!(matches!(
            rule("||ads.example.com^").target,
            Target::Suffix(_)
        ));
    }

    #[test]
    fn modifier_labels_are_bounded() {
        assert_eq!(
            SkipReason::Modifier("DNSTYPE".into()).label(),
            "modifier:dnstype"
        );
        assert_eq!(
            SkipReason::Modifier("third-party".into()).label(),
            "modifier:third-party"
        );
        assert_eq!(
            SkipReason::Modifier("random-list-text".into()).label(),
            "modifier:other"
        );
    }

    #[test]
    fn skip_labels_are_stable() {
        assert_eq!(SkipReason::Regex.label(), "regex");
        assert_eq!(SkipReason::UrlPath.label(), "url_path");
        assert_eq!(SkipReason::Invalid.label(), "invalid");
        assert_eq!(
            SkipReason::Modifier("client".into()).label(),
            "modifier:client"
        );
    }
}
