//! The TOML config: parsed once at startup, validated, then passed around as plain data.

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

// `deny_unknown_fields` turns a typo like `row_capp` into a load error
// instead of a silently ignored setting.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub dns: DnsConfig,
    pub upstreams: UpstreamConfig,
    #[serde(default)]
    pub lists: Vec<ListConfig>,
    #[serde(default)]
    pub user_rules: Vec<String>,
    #[serde(default)]
    pub rewrites: Vec<Rewrite>,
    /// Friendly names for client IPs, shown in the query log.
    #[serde(default)]
    #[allow(dead_code)] // Read by Task 10's device names.
    pub devices: BTreeMap<IpAddr, String>,
    pub api: ApiConfig,
    pub store: StoreConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub listen: SocketAddr,
    /// Names answered with REFUSED (version.bind and friends).
    #[serde(default)]
    pub refused_names: Vec<String>,
    pub blocked_ttl: u32,
    pub max_inflight: usize,
    /// The router's address, used for local PTR answers.
    #[allow(dead_code)] // Read by Task 10's device names.
    pub router: IpAddr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    #[serde(default)]
    pub doh: Vec<DohUpstream>,
    #[serde(default)]
    pub fallback: Vec<SocketAddr>,
    pub race_timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DohUpstream {
    pub url: String,
    /// IPs used to reach the DoH host, so resolving its name does not need DNS.
    #[serde(default)]
    pub bootstrap: Vec<IpAddr>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListConfig {
    pub id: u32,
    pub name: String,
    pub url: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    /// An exact name, or `*.suffix` to match every name below the suffix.
    pub name: String,
    pub a: Ipv4Addr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Read by Tasks 11 and 12 (query executor, API).
pub struct ApiConfig {
    pub listen: SocketAddr,
    pub secret_file: PathBuf,
    pub query_timeout_ms: u64,
    pub row_cap: usize,
    pub max_concurrent: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    pub path: PathBuf,
    pub raw_days: u32,
    pub rollup_days: u32,
    pub lists_dir: PathBuf,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.dns.max_inflight > 0,
            "dns.max_inflight must be above 0"
        );
        ensure!(
            !self.upstreams.doh.is_empty() || !self.upstreams.fallback.is_empty(),
            "upstreams needs at least one doh or fallback server"
        );
        ensure!(
            self.upstreams.race_timeout_ms > 0,
            "upstreams.race_timeout_ms must be above 0"
        );
        for d in &self.upstreams.doh {
            ensure!(
                d.url.starts_with("https://"),
                "doh url must be https: {}",
                d.url
            );
            // Without a pinned address reqwest would resolve the host through the system
            // resolver, which is sieve itself.
            let host = reqwest::Url::parse(&d.url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .with_context(|| format!("bad doh url {}", d.url))?;
            let is_ip = host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok();
            ensure!(
                is_ip || !d.bootstrap.is_empty(),
                "doh {} needs bootstrap addresses (its host is a name)",
                d.url
            );
        }
        ensure!(self.api.row_cap > 0, "api.row_cap must be above 0");
        ensure!(
            self.api.max_concurrent > 0,
            "api.max_concurrent must be above 0"
        );

        let mut seen = std::collections::BTreeSet::new();
        for l in &self.lists {
            ensure!(seen.insert(l.id), "duplicate list id {}", l.id);
        }
        for r in &self.rewrites {
            validate_rewrite_name(&r.name)?;
        }
        Ok(())
    }
}

/// Only a single leading `*.` is a wildcard, and it must have a suffix after it.
fn validate_rewrite_name(name: &str) -> Result<()> {
    let body = name.strip_prefix("*.").unwrap_or(name);
    if body.is_empty() || body.contains('*') || body.split('.').any(str::is_empty) {
        bail!("bad rewrite name {name:?}: use an exact name or a leading \"*.\" only");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const DEPLOY: &str = include_str!("../deploy/config.toml");

    #[test]
    fn parses_deploy_config() {
        let c = Config::load(Path::new("deploy/config.toml")).expect("deploy config loads");
        assert_eq!(c.upstreams.doh.len(), 2);
        assert!(c.lists.iter().any(|l| l.id == 1 && l.enabled));
        assert_eq!(c.rewrites.len(), 2);
    }

    #[test]
    fn rejects_duplicate_list_ids() {
        let text = DEPLOY.replace("id = 2", "id = 1");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_rewrite_with_bad_wildcard() {
        let text = DEPLOY.replace("\"*.home.riddlelab.dev\"", "\"a.*.b\"");
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(err.contains("a.*.b"), "{err}");
    }

    #[test]
    fn rejects_zero_race_timeout() {
        let text = DEPLOY.replace("race_timeout_ms = 1000", "race_timeout_ms = 0");
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(err.contains("race_timeout_ms"), "{err}");
    }

    #[test]
    fn rejects_doh_without_bootstrap_unless_ip_literal() {
        let bare = DEPLOY.replace(
            "bootstrap = [\"9.9.9.10\", \"149.112.112.10\"]",
            "bootstrap = []",
        );
        assert_ne!(bare, DEPLOY, "fixture text moved");
        let err = Config::parse(&bare).unwrap_err().to_string();
        assert!(err.contains("bootstrap"), "{err}");
        let literal = bare.replace(
            "https://dns10.quad9.net/dns-query",
            "https://9.9.9.10/dns-query",
        );
        assert!(Config::parse(&literal).is_ok());
    }

    #[test]
    fn rejects_zero_row_cap() {
        let text = DEPLOY.replace("row_cap = 10000", "row_cap = 0");
        assert!(Config::parse(&text).is_err());
    }
}
