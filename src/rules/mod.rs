//! Filter-list rules: parsing one line, then matching names against a built set.

mod engine;
mod parse;

#[allow(unused_imports)]
pub use engine::{ListStats, RuleSet, Verdict};
#[allow(unused_imports)]
pub use parse::{parse_line, Parsed, Rule, RuleKind, SkipReason};
