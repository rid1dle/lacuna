//! Filter-list rules: parsing one line (this task) and matching names (next).

mod parse;

// Consumed by the rule engine in the next task.
#[allow(unused_imports)]
pub use parse::{parse_line, Parsed, Rule, RuleKind, SkipReason};
