//! Filter-list rules: parsing one line, then matching names against a built set.

mod engine;
mod parse;

pub use engine::{ListStats, RuleSet, Verdict};
pub use parse::{parse_line, Parsed, Rule, RuleKind, SkipReason};
