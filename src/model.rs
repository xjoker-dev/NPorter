//! Configuration data model and (de)serialization helpers.
//!
//! Format is TOML. Durations are written/read as human strings ("10s", "24h",
//! "90d") via the [`HumanDuration`] newtype.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Comment marker stamped onto every nftables rule we own, so we can identify
/// and reconcile our rules without touching anyone else's.
pub const COMMENT_PREFIX: &str = "nporter:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            other => Err(format!("unsupported protocol {other:?} (want tcp or udp)")),
        }
    }
}

/// A single port-forwarding rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub protocol: Protocol,
    pub listen_ip: String,
    pub listen_port: u16,
    pub target_ip: String,
    pub target_port: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub masquerade: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub nftables: NftablesConfig,
    pub ufw: UfwConfig,
    pub prometheus: PrometheusConfig,
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NftablesConfig {
    /// nftables family. We use `inet` for dual-stack (IPv4 + IPv6).
    pub family: String,
    pub table_name: String,
    pub enable_ip_forward: bool,
    pub default_masquerade: bool,
}

impl Default for NftablesConfig {
    fn default() -> Self {
        NftablesConfig {
            family: "inet".to_string(),
            table_name: "nporter".to_string(),
            enable_ip_forward: true,
            default_masquerade: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UfwConfig {
    /// Reconcile UFW route allow rules for enabled mappings during apply.
    pub manage: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrometheusConfig {
    pub enabled: bool,
    pub listen_address: String,
    pub path: String,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        PrometheusConfig {
            enabled: false,
            listen_address: "127.0.0.1:9090".to_string(),
            path: "/metrics".to_string(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_parse() {
        assert_eq!("TCP".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert!("sctp".parse::<Protocol>().is_err());
    }
}
