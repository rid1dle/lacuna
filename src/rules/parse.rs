//! One line of a uBlock/AdGuard filter list, DNS subset.

use std::net::IpAddr;

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
    /// Lowercase, no trailing dot.
    pub domain: String,
    pub kind: RuleKind,
    pub important: bool,
    pub badfilter: bool,
    /// The original line, trimmed.
    pub text: String,
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
    Wildcard,
    UrlPath,
    Invalid,
}

impl SkipReason {
    /// Stable key for skip counters.
    pub fn label(&self) -> String {
        match self {
            SkipReason::Regex => "regex".into(),
            SkipReason::Modifier(name) => format!("modifier:{name}"),
            SkipReason::Wildcard => "wildcard".into(),
            SkipReason::UrlPath => "url_path".into(),
            SkipReason::Invalid => "invalid".into(),
        }
    }
}

/// Names a hosts file lists for the machine itself; they are not ad rules.
fn is_hosts_boilerplate(name: &str) -> bool {
    matches!(name, "localhost" | "localhost.localdomain" | "broadcasthost" | "local")
        || name.starts_with("ip6-")
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

    let (pattern, modifiers) = match rest.rsplit_once('$') {
        Some((pattern, mods)) => (pattern, Some(mods)),
        None => (rest, None),
    };

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

    let pattern = pattern.strip_prefix("||").unwrap_or(pattern);
    let pattern = pattern.strip_suffix('^').unwrap_or(pattern);
    if pattern.contains('/') {
        return Parsed::Skip(SkipReason::UrlPath);
    }
    if pattern.contains('*') {
        return Parsed::Skip(SkipReason::Wildcard);
    }
    let Some(domain) = normalize_domain(pattern) else {
        return Parsed::Skip(SkipReason::Invalid);
    };

    Parsed::Rule(Rule {
        domain,
        kind: if allow { RuleKind::Allow } else { RuleKind::Block },
        important,
        badfilter,
        text: text.to_string(),
    })
}

fn parse_hosts(text: &str) -> Parsed {
    // Hosts files allow a trailing "# comment".
    let body = text.split('#').next().unwrap_or(text);
    let mut tokens = body.split_whitespace();
    let (Some(addr), Some(name), None) = (tokens.next(), tokens.next(), tokens.next()) else {
        return Parsed::Skip(SkipReason::Invalid);
    };
    if is_hosts_boilerplate(&name.to_ascii_lowercase()) {
        return Parsed::Blank;
    }
    let (Ok(ip), Some(domain)) = (addr.parse::<IpAddr>(), normalize_domain(name)) else {
        return Parsed::Skip(SkipReason::Invalid);
    };
    Parsed::Rule(Rule {
        domain,
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
        && name.split('.').all(|label| !label.is_empty() && label.len() <= 63)
        && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'));
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
        assert_eq!(r.domain, "ads.example.com");
        assert_eq!(r.kind, RuleKind::Block);
        assert!(!r.important);
        assert!(!r.badfilter);
        assert_eq!(r.text, "||ads.example.com^");
    }

    #[test]
    fn exception_allows() {
        let r = rule("@@||ok.example.com^");
        assert_eq!(r.domain, "ok.example.com");
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
        assert_eq!(rule("0.0.0.0\ttracker.net # trailing").domain, "tracker.net");
        let r = rule("10.1.2.3 intranet.example");
        assert_eq!(r.kind, RuleKind::HostsIp("10.1.2.3".parse().unwrap()));
        assert_eq!(r.domain, "intranet.example");
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
    fn plain_domain_blocks() {
        assert_eq!(rule("plain.example.org").domain, "plain.example.org");
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
        assert_eq!(skip("||x.com^$important,client=1.2.3.4"), SkipReason::Modifier("client".into()));
    }

    #[test]
    fn wildcard_and_url_path_skipped() {
        assert_eq!(skip("||ad*.example.com^"), SkipReason::Wildcard);
        assert_eq!(skip("||example.com/ads/"), SkipReason::UrlPath);
    }

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(rule("||EXAMPLE.Com.^").domain, "example.com");
    }

    #[test]
    fn invalid_shapes() {
        for line in ["||^", "||.example.com^", "||a..b^", "||exa mple.com^", "||bücher.de^", "||x.com^$", "garbage line here"] {
            assert_eq!(skip(line), SkipReason::Invalid, "{line}");
        }
        assert!(matches!(parse_line("||xn--bcher-kva.de^"), Parsed::Rule(_)));
        assert!(matches!(parse_line("||a_b.c-d.com^"), Parsed::Rule(_)));
    }

    #[test]
    fn skip_labels_are_stable() {
        assert_eq!(SkipReason::Regex.label(), "regex");
        assert_eq!(SkipReason::Wildcard.label(), "wildcard");
        assert_eq!(SkipReason::UrlPath.label(), "url_path");
        assert_eq!(SkipReason::Invalid.label(), "invalid");
        assert_eq!(SkipReason::Modifier("client".into()).label(), "modifier:client");
    }
}
