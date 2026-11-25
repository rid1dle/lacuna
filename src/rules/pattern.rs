//! AdGuard basic-rule patterns (`||*ads.example^`, `|cdn.x.com^|`, `.d^`), matched against
//! a hostname exactly as AdGuard Home's filtering library does.
//!
//! Confirmed in the source, AdguardTeam/urlfilter at 347285f (2026-08-19):
//! - `rules/regexp.go` `patternToRegexp` turns a pattern into a regex: `*` is `.*`; `^` is
//!   `([^ a-zA-Z0-9.%_-]|$)`, one separator character or the end of the input; a leading `|`
//!   is `^`, a trailing `|` is `$`, and any other `|` is a literal pipe; `||` is
//!   `^(http|https|ws|wss)://([a-z0-9-_.]+\.)?`. Everything else is literal, and the regex
//!   is case-insensitive.
//! - `rules/network.go` `matchPattern` and `shouldMatchHostname`: a DNS lookup is the request
//!   "http://" + hostname. A pattern starting with `||` is matched against that URL, any
//!   other pattern against the bare hostname, unanchored unless `|` anchors it. So `||p`
//!   matches p at the start of the name or right after a dot, `|p` only at the start, and
//!   `p` anywhere: `.d^` matches `x.d` but not `d`. A pattern with no `^` or trailing `|`
//!   may end mid-name, so `||ads.` matches `ads.example.com`.
//! - `rules/network.go` `hasURLPrefix`: `://` patterns are also matched against the URL,
//!   where `://` sits right before the host, so `://p` is `|p` on the name.
//! - `rules/network.go` `isPatternTooWide`: patterns shorter than 3 characters are rejected.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchor {
    /// No leading `|`: the pattern may start anywhere in the name.
    Anywhere,
    /// `|`: only at the very start.
    Start,
    /// `||`: at the start or right after a dot.
    Label,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    /// Lowercase hostname characters, matched literally.
    Text(Box<str>),
    /// `*`: any run of characters, the empty run included.
    Any,
    /// `^`: one separator character, or the end of the name.
    Separator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    anchor: Anchor,
    parts: Box<[Part]>,
    /// A trailing `|`: the match must reach the end of the name.
    to_end: bool,
}

/// Characters `([a-z0-9-_.]+\.)?` may skip over before a `||` pattern starts.
fn is_host_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
}

/// What `^` accepts: anything but a letter, a digit, space or one of `.%_-`.
fn is_separator(b: u8) -> bool {
    !(b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'%' | b'_' | b'-'))
}

impl Pattern {
    /// The pattern part of a rule (no `@@`, no `$` modifiers). None for a pattern AdGuard
    /// rejects as too wide, one with no literal text, or one with a character no hostname
    /// can hold (a mid-pattern `|`, `%`, non-ASCII): those could never match a name.
    pub fn parse(raw: &str) -> Option<Pattern> {
        if raw.len() < 3 {
            return None;
        }
        let lower = raw.to_ascii_lowercase();
        if let Some(body) = lower.strip_prefix("||") {
            Self::build(Anchor::Label, body)
        } else if let Some(body) = lower.strip_prefix('|') {
            Self::build(Anchor::Start, body)
        } else {
            Self::build(Anchor::Anywhere, &lower)
        }
    }

    /// The part after `://` of a `://host^` rule. AdGuard matches those against
    /// "http://" + hostname (`hasURLPrefix` in rules/network.go), where `://` occurs once,
    /// right before the host, so the rest is anchored at the start of the name.
    pub fn parse_after_scheme(rest: &str) -> Option<Pattern> {
        Self::build(Anchor::Start, &rest.to_ascii_lowercase())
    }

    /// `body` is lowercase, without its leading anchor.
    fn build(anchor: Anchor, body: &str) -> Option<Pattern> {
        let (body, to_end) = match body.strip_suffix('|') {
            Some(body) => (body, true),
            None => (body, false),
        };

        let mut parts = Vec::new();
        let mut text = String::new();
        for c in body.chars() {
            let special = match c {
                '*' => Part::Any,
                '^' => Part::Separator,
                'a'..='z' | '0'..='9' | '-' | '_' | '.' => {
                    text.push(c);
                    continue;
                }
                _ => return None,
            };
            if !text.is_empty() {
                parts.push(Part::Text(std::mem::take(&mut text).into_boxed_str()));
            }
            // `**` is the same as `*`.
            if !(special == Part::Any && parts.last() == Some(&Part::Any)) {
                parts.push(special);
            }
        }
        if !text.is_empty() {
            parts.push(Part::Text(text.into_boxed_str()));
        }
        if !parts.iter().any(|p| matches!(p, Part::Text(_))) {
            return None;
        }
        Some(Pattern {
            anchor,
            parts: parts.into_boxed_slice(),
            to_end,
        })
    }

    /// The longest literal run: every name this pattern matches contains it.
    fn longest_text(&self) -> &str {
        self.parts
            .iter()
            .filter_map(|p| match p {
                Part::Text(t) => Some(&**t),
                _ => None,
            })
            .max_by_key(|t| t.len())
            .unwrap_or("")
    }

    /// `name` is lowercase with no trailing dot.
    ///
    /// Runs like a regex engine without backtracking. `live[i]` says some way of matching
    /// the parts so far ends at byte `i`; each part turns that set into the next in one pass
    /// over the name, so the cost is O(parts x name length) however many `*` there are. A
    /// backtracking matcher is exponential in the number of `*`, and a list line plus a
    /// name any web page can make a browser look up would stall the DNS worker.
    pub fn matches(&self, name: &str) -> bool {
        // Two position sets on the stack for any real DNS name (at most 253 bytes).
        const STACK: usize = 256;
        let len = name.len() + 1;
        if len <= STACK {
            let (mut live, mut next) = ([false; STACK], [false; STACK]);
            self.run(name.as_bytes(), &mut live[..len], &mut next[..len])
        } else {
            self.run(
                name.as_bytes(),
                &mut vec![false; len],
                &mut vec![false; len],
            )
        }
    }

    /// `live` and `next` are all false, one longer than `name`.
    fn run<'a>(&self, name: &[u8], mut live: &'a mut [bool], mut next: &'a mut [bool]) -> bool {
        let end = name.len();
        match self.anchor {
            Anchor::Start => live[0] = true,
            // An unanchored pattern may start anywhere, as if it began with `*`.
            Anchor::Anywhere => live.fill(true),
            Anchor::Label => {
                live[0] = true;
                // The optional `([a-z0-9-_.]+\.)` prefix: at least one host character, then
                // a dot. It cannot cross a character outside that set.
                for (i, &b) in name.iter().enumerate() {
                    if !is_host_byte(b) {
                        break;
                    }
                    if b == b'.' && i > 0 {
                        live[i + 1] = true;
                    }
                }
            }
        }

        for part in self.parts.iter() {
            next.fill(false);
            match part {
                Part::Text(t) => {
                    let t = t.as_bytes();
                    for (i, _) in live.iter().enumerate().filter(|(_, &l)| l) {
                        if name[i..].starts_with(t) {
                            next[i + t.len()] = true;
                        }
                    }
                }
                Part::Separator => {
                    for (i, &b) in name.iter().enumerate() {
                        if live[i] && is_separator(b) {
                            next[i + 1] = true;
                        }
                    }
                    // `$`: zero width, only at the end.
                    next[end] |= live[end];
                }
                // `*` reaches every position from the first live one on.
                Part::Any => {
                    if let Some(first) = live.iter().position(|&l| l) {
                        next[first..].fill(true);
                    }
                }
            }
            std::mem::swap(&mut live, &mut next);
            if !live.contains(&true) {
                return false;
            }
        }
        if self.to_end {
            live[end]
        } else {
            true
        }
    }
}

/// Bytes per index key. Every literal in the AdGuard DNS filter is at least this long.
const WINDOW: usize = 5;

/// Patterns with a value each, indexed so a lookup tries only the few that could match.
///
/// Each pattern is filed under one `WINDOW`-byte slice of its longest literal. A name can
/// only match patterns filed under a slice the name contains, so a lookup reads the
/// buckets for each of the name's windows (about 30 for a typical name) instead of every
/// pattern. Patterns with no literal that long are tried on every name.
#[derive(Debug)]
pub struct PatternTable<T> {
    entries: Vec<(Pattern, T)>,
    by_window: HashMap<[u8; WINDOW], Vec<u32>>,
    short: Vec<u32>,
}

impl<T> Default for PatternTable<T> {
    fn default() -> Self {
        PatternTable {
            entries: Vec::new(),
            by_window: HashMap::new(),
            short: Vec::new(),
        }
    }
}

impl<T> PatternTable<T> {
    pub fn insert(&mut self, pattern: Pattern, value: T) {
        let id = self.entries.len() as u32;
        // Any window of the literal is correct; the least crowded one keeps buckets short.
        let key = pattern
            .longest_text()
            .as_bytes()
            .windows(WINDOW)
            .filter_map(|w| <[u8; WINDOW]>::try_from(w).ok())
            .min_by_key(|k| self.by_window.get(k).map_or(0, Vec::len));
        match key {
            Some(key) => self.by_window.entry(key).or_default().push(id),
            None => self.short.push(id),
        }
        self.entries.push((pattern, value));
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Calls `found` with the value of every pattern that matches `name` (lowercase, no
    /// trailing dot). A pattern may be reported twice when its window occurs twice.
    pub fn for_each_match(&self, name: &str, mut found: impl FnMut(&T)) {
        if self.entries.is_empty() {
            return;
        }
        // `[u8; N]` hashes like the slice `[u8]`, so a window of the name is a valid key.
        let candidates = name
            .as_bytes()
            .windows(WINDOW)
            .filter_map(|w| self.by_window.get(w))
            .flatten()
            .chain(&self.short);
        for &id in candidates {
            if let Some((pattern, value)) = self.entries.get(id as usize) {
                if pattern.matches(name) {
                    found(value);
                }
            }
        }
    }

    /// Rough heap bytes, for sizing checks.
    pub fn estimated_bytes(&self) -> usize {
        let parts: usize = self
            .entries
            .iter()
            .flat_map(|(p, _)| p.parts.iter())
            .map(|part| {
                std::mem::size_of::<Part>()
                    + match part {
                        Part::Text(t) => t.len(),
                        _ => 0,
                    }
            })
            .sum();
        self.entries.capacity() * std::mem::size_of::<(Pattern, T)>()
            + parts
            + self.by_window.capacity() * (std::mem::size_of::<([u8; WINDOW], Vec<u32>)>() + 1)
            + self
                .by_window
                .values()
                .map(|v| v.capacity() * 4)
                .sum::<usize>()
            + self.short.capacity() * 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(raw: &str) -> Pattern {
        Pattern::parse(raw).unwrap_or_else(|| panic!("{raw:?} did not parse"))
    }

    #[test]
    fn label_anchor_starts_at_a_dot_or_the_start() {
        let pat = p("||ads.");
        assert!(pat.matches("ads.example.com"));
        assert!(pat.matches("x.ads.example.com"));
        assert!(!pat.matches("xads.example.com"));
        assert!(!pat.matches("ads"));
        // The skipped prefix is `[a-z0-9-_.]+\.`: it needs a character before the dot and
        // cannot cross anything else.
        assert!(!pat.matches(".ads.x"));
        assert!(!pat.matches("a b.ads.x"));
    }

    #[test]
    fn separator_is_the_end_or_one_separator_character() {
        let pat = p("||example.com^");
        assert!(pat.matches("example.com"));
        assert!(!pat.matches("example.community"));
        assert!(!pat.matches("example.com.au"));
        assert!(pat.matches("example.com:53"));
        // `-` is not a separator.
        assert!(!pat.matches("example.com-x"));
    }

    #[test]
    fn pipes_anchor_start_and_end() {
        let pat = p("|cdn.taboola.com^|");
        assert!(pat.matches("cdn.taboola.com"));
        assert!(!pat.matches("x.cdn.taboola.com"));
        let pat = p("ads.example|");
        assert!(pat.matches("x-ads.example"));
        assert!(!pat.matches("ads.example.org"));
    }

    #[test]
    fn wildcards_backtrack() {
        let pat = p("||a*b*c^");
        assert!(pat.matches("a-b-b-c"));
        assert!(pat.matches("abc"));
        assert!(!pat.matches("a-c-b"));
        assert!(!pat.matches("ab-cd"));
        assert!(p("||aan.amazon.*^").matches("aan.amazon.co.uk"));
        assert!(p("||x**y^").matches("x.y"));
    }

    #[test]
    fn unanchored_matches_anywhere() {
        let pat = p(".skadsdkless.appsflyersdk.com^");
        assert!(pat.matches("a.skadsdkless.appsflyersdk.com"));
        assert!(!pat.matches("skadsdkless.appsflyersdk.com"));
        // Overlapping candidates: the second "aa" is the one that fits.
        assert!(p("aab^").matches("aaab"));
    }

    /// Runs `f` on a thread and fails if it takes longer than `limit`, so a regression
    /// fails the test instead of hanging the suite.
    fn finishes_within(
        limit: std::time::Duration,
        f: impl FnOnce() -> bool + Send + 'static,
    ) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(limit)
            .unwrap_or_else(|_| panic!("did not finish within {limit:?}"))
    }

    #[test]
    fn matching_is_linear_in_stars_and_name_length() {
        let limit = std::time::Duration::from_millis(5);
        // 20 stars against a 253-character run of the first literal: exponential
        // backtracking would never finish.
        let raw = format!("{}b^", "a*".repeat(20));
        let pat = p(&raw);
        let name = "a".repeat(253);
        assert!(!finishes_within(limit, move || pat.matches(&name)));
        let pat = p(&raw);
        let name = "a".repeat(252) + "b";
        assert!(finishes_within(limit, move || pat.matches(&name)));
        let pat = p("||a*.a*.a*.a*.a*.a*.a*.a*.a*.a*.x^");
        let name = "a.".repeat(126) + "a";
        assert!(!finishes_within(limit, move || pat.matches(&name)));
    }

    #[test]
    fn rejects_what_cannot_match_a_name() {
        for raw in [
            "",
            "|",
            "||",
            "*",
            "ab",
            "||^",
            "||*^",
            "a|b.com",
            "a%b.com",
            "bücher.de",
        ] {
            assert_eq!(Pattern::parse(raw), None, "{raw:?}");
        }
        assert!(p("||EXAMPLE.*^").matches("example.org"));
    }

    #[test]
    fn table_finds_long_and_short_patterns() {
        let mut t = PatternTable::default();
        t.insert(p("||*cdn-settings.appsflyersdk.com^"), 1);
        t.insert(p("||ad.x*"), 2);
        t.insert(p("||sdk-*.moengage.com^"), 3);
        let hits = |name: &str| {
            let mut v = Vec::new();
            t.for_each_match(name, |&x| v.push(x));
            v.sort();
            v.dedup();
            v
        };
        assert_eq!(hits("k-cdn-settings.appsflyersdk.com"), vec![1]);
        assert_eq!(hits("ad.xyz"), vec![2]);
        assert_eq!(hits("sdk-01.moengage.com"), vec![3]);
        assert_eq!(hits("example.com"), Vec::<i32>::new());
        assert_eq!(t.short.len(), 1);
    }
}
