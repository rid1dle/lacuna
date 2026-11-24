//! Filter-list rules: parsing one line, then matching names against a built set.

mod engine;
mod parse;

#[allow(unused_imports)] // Task 9's refresh report carries ListStats.
pub use engine::ListStats;
pub use engine::{RuleSet, Verdict};
pub use parse::{parse_line, Parsed, Rule, RuleKind};
