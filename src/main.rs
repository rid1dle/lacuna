// The config and codes are consumed by later tasks; silence dead-code noise until then.
#![allow(dead_code)]

mod codes;
mod config;
mod rules;

use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage: sieve <check-config <path> | serve <path>>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Matching on a slice of `&str` keeps the subcommand table readable without clap.
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["check-config", path] => match config::Config::load(Path::new(path)) {
            Ok(_) => {
                println!("ok");
                ExitCode::SUCCESS
            }
            Err(e) => {
                // `{:#}` prints the whole context chain on one line.
                println!("{e:#}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
