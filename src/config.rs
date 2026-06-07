//! Config file loading, saving and validation (TOML).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::model::{Config, Mapping, Protocol};
use crate::nft::ruleset::is_safe_id;

/// Load and validate the config at `path`.
pub fn load(path: &Path) -> Result<Config> {
    let data =
        fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&data).with_context(|| format!("parsing config {}", path.display()))?;
    validate(&cfg)?;
    Ok(cfg)
}

/// Load the config, creating an empty default one if the file does not exist.
/// Returns `(config, created)`.
pub fn load_or_create(path: &Path) -> Result<(Config, bool)> {
    match load(path) {
        Ok(cfg) => Ok((cfg, false)),
        Err(e) => {
            // Only auto-create on "file not found"; surface every other error.
            let is_missing = e
                .downcast_ref::<std::io::Error>()
                .map(|io| io.kind() == std::io::ErrorKind::NotFound)
                .unwrap_or(false);
            if !is_missing {
                return Err(e);
            }
            let cfg = Config::default();
            save(path, &cfg)?;
            Ok((cfg, true))
        }
    }
}

/// Validate and write the config to `path` (creating parent dirs).
pub fn save(path: &Path, cfg: &Config) -> Result<()> {
    validate(cfg)?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating config dir {}", parent.display()))?;
    }
    let data = toml::to_string_pretty(cfg).context("serializing config")?;
    // Write to a temp file then rename, so a crash/power-loss mid-write cannot
    // leave a truncated, unparseable config (which would block the daemon).
    let tmp = path.with_extension("toml.tmp");
    write_private_file(&tmp, &data).with_context(|| format!("writing config {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replacing config {}", path.display()))?;
    set_private_permissions(path)
        .with_context(|| format!("setting config permissions {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, data: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, data: &str) -> Result<()> {
    fs::write(path, data)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Address family a mapping operates on, derived from its target IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Mapping {
    /// Family of this mapping, derived from `target_ip`.
    pub fn family(&self) -> Result<Family> {
        match self.target_ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => Ok(Family::V4),
            Ok(IpAddr::V6(_)) => Ok(Family::V6),
            Err(_) => bail!(
                "mapping {} target_ip is invalid: {}",
                self.id,
                self.target_ip
            ),
        }
    }
}

pub fn validate(cfg: &Config) -> Result<()> {
    if cfg.nftables.family.is_empty() {
        bail!("nftables.family is required");
    }
    if cfg.nftables.family != "inet" && cfg.nftables.family != "ip" && cfg.nftables.family != "ip6"
    {
        bail!(
            "nftables.family {:?} is not supported (use inet, ip or ip6)",
            cfg.nftables.family
        );
    }
    if cfg.nftables.table_name.is_empty() {
        bail!("nftables.table_name is required");
    }
    if cfg.prometheus.path.is_empty() {
        bail!("prometheus.path is required");
    }
    if !cfg.prometheus.path.starts_with('/') {
        bail!("prometheus.path must start with /");
    }
    if cfg.prometheus.enabled && cfg.prometheus.listen_address.is_empty() {
        bail!("prometheus.listen_address is required when enabled");
    }

    let mut seen_endpoint: HashMap<String, String> = HashMap::new();
    let mut seen_id: HashSet<String> = HashSet::new();
    for m in &cfg.mappings {
        validate_mapping(m)?;
        // Mapping ids must be unique (they label metrics/stats and key rule
        // reconciliation) and use a conservative charset (they go into rule
        // comments parsed by whitespace). Checked here — the single gate that
        // CLI, TUI and `apply` all pass through.
        if !is_safe_id(&m.id) {
            bail!(
                "mapping {} id has unsupported characters (use [A-Za-z0-9._-], start alnum)",
                m.id
            );
        }
        if !seen_id.insert(m.id.clone()) {
            bail!("duplicate mapping id: {}", m.id);
        }
        // ip family table cannot carry v6 mappings and vice versa.
        let fam = m.family()?;
        match (cfg.nftables.family.as_str(), fam) {
            ("ip", Family::V6) => bail!("mapping {} is IPv6 but nftables.family is ip", m.id),
            ("ip6", Family::V4) => bail!("mapping {} is IPv4 but nftables.family is ip6", m.id),
            _ => {}
        }
        let key = format!("{}/{}/{}", m.listen_ip, m.protocol, m.listen_port);
        if let Some(prev) = seen_endpoint.insert(key, m.id.clone()) {
            bail!(
                "listen endpoint conflict: {} conflicts with mapping {}",
                m.id,
                prev
            );
        }
    }
    Ok(())
}

fn validate_mapping(m: &Mapping) -> Result<()> {
    if m.id.is_empty() {
        bail!("mapping id is required");
    }
    if m.protocol != Protocol::Tcp && m.protocol != Protocol::Udp {
        bail!("mapping {} has unsupported protocol {}", m.id, m.protocol);
    }
    if m.listen_ip.is_empty() {
        bail!("mapping {} listen_ip is required", m.id);
    }
    let listen: IpAddr = m
        .listen_ip
        .parse()
        .map_err(|_| anyhow::anyhow!("mapping {} listen_ip is invalid: {}", m.id, m.listen_ip))?;
    let target: IpAddr = m
        .target_ip
        .parse()
        .map_err(|_| anyhow::anyhow!("mapping {} target_ip is invalid: {}", m.id, m.target_ip))?;
    // listen and target must agree on address family — we cannot DNAT v4->v6.
    if listen.is_ipv4() != target.is_ipv4() {
        bail!(
            "mapping {} mixes IPv4 and IPv6 (listen {} / target {})",
            m.id,
            m.listen_ip,
            m.target_ip
        );
    }
    if m.listen_port == 0 {
        bail!("mapping {} listen_port must be 1-65535", m.id);
    }
    if m.target_port == 0 {
        bail!("mapping {} target_port must be 1-65535", m.id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;

    fn sample() -> Mapping {
        Mapping {
            id: "r1".into(),
            name: "Rule 1".into(),
            protocol: Protocol::Tcp,
            listen_ip: "0.0.0.0".into(),
            listen_port: 8080,
            target_ip: "192.0.2.10".into(),
            target_port: 80,
            enabled: true,
            masquerade: true,
            description: String::new(),
        }
    }

    #[test]
    fn validate_ok_and_roundtrip() {
        let mut cfg = Config::default();
        cfg.mappings.push(sample());
        validate(&cfg).unwrap();
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.mappings.len(), 1);
        assert_eq!(back.nftables.family, "inet");
    }

    #[test]
    fn rejects_mixed_family() {
        let mut m = sample();
        m.target_ip = "fd00::1".into();
        let mut cfg = Config::default();
        cfg.mappings.push(m);
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_listen_conflict() {
        let mut cfg = Config::default();
        let mut a = sample();
        a.id = "a".into();
        let mut b = sample();
        b.id = "b".into();
        cfg.mappings.push(a);
        cfg.mappings.push(b);
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn v6_mapping_ok_on_inet() {
        let mut m = sample();
        m.listen_ip = "::".into();
        m.target_ip = "fd00::1".into();
        let mut cfg = Config::default();
        cfg.mappings.push(m);
        validate(&cfg).unwrap();
    }
}
