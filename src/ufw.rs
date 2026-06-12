//! Optional UFW route-rule reconciliation.
//!
//! UFW evaluates forwarded packets after NPorter's DNAT chain. When UFW's
//! routed policy is deny, enabled mappings need matching route allow rules.

use std::collections::HashSet;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};

use crate::model::{Config, Mapping};

const COMMENT_PREFIX: &str = "NPorter:";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rule {
    protocol: String,
    target_ip: String,
    target_port: u16,
}

impl Rule {
    fn from_mapping(m: &Mapping) -> Self {
        Rule {
            protocol: m.protocol.to_string(),
            target_ip: m.target_ip.clone(),
            target_port: m.target_port,
        }
    }

    fn comment(&self) -> String {
        let spec = format!("{}|{}|{}", self.protocol, self.target_ip, self.target_port);
        format!("{COMMENT_PREFIX}{:016x}", crate::nft::fnv1a(&spec))
    }

    fn args(&self) -> Vec<String> {
        vec![
            "allow".into(),
            "proto".into(),
            self.protocol.clone(),
            "to".into(),
            self.target_ip.clone(),
            "port".into(),
            self.target_port.to_string(),
            "comment".into(),
            self.comment(),
        ]
    }

    pub fn display_command(&self) -> String {
        format!("ufw route {}", self.args().join(" "))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ApplyReport {
    pub added: usize,
    pub deleted: usize,
    pub kept: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    add: Vec<Rule>,
    delete: Vec<Rule>,
    kept: usize,
}

pub fn desired_rules(cfg: &Config) -> Vec<Rule> {
    let mut rules: Vec<_> = cfg
        .mappings
        .iter()
        .filter(|m| m.enabled)
        .map(Rule::from_mapping)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    rules.sort_by(|a, b| {
        a.protocol
            .cmp(&b.protocol)
            .then(a.target_ip.cmp(&b.target_ip))
            .then(a.target_port.cmp(&b.target_port))
    });
    rules
}

pub fn apply(cfg: &Config) -> Result<ApplyReport> {
    if !cfg.ufw.manage {
        return Ok(ApplyReport::default());
    }

    let observed = observed_rules()?;
    let plan = build_plan(desired_rules(cfg), observed);

    // Add desired rules before deleting stale rules. A partial failure remains
    // permissive only for mappings that were previously allowed.
    for rule in &plan.add {
        run_rule("adding", rule, false)?;
    }
    for rule in &plan.delete {
        run_rule("deleting", rule, true)?;
    }

    Ok(ApplyReport {
        added: plan.add.len(),
        deleted: plan.delete.len(),
        kept: plan.kept,
    })
}

fn observed_rules() -> Result<Vec<Rule>> {
    let output = command()?
        .args(["show", "added"])
        .env("LC_ALL", "C")
        .output()
        .context("running `ufw show added` (install ufw or set ufw.manage=false)")?;
    ensure_success("listing UFW rules", &output)?;
    let stdout = String::from_utf8(output.stdout).context("decoding `ufw show added` output")?;
    Ok(parse_added(&stdout))
}

fn run_rule(action: &str, rule: &Rule, delete: bool) -> Result<()> {
    let mut args = vec!["--force".to_string(), "route".to_string()];
    if delete {
        args.push("delete".to_string());
    }
    args.extend(rule.args());
    let output = command()?
        .args(&args)
        .env("LC_ALL", "C")
        .output()
        .with_context(|| format!("{action} UFW rule {}", rule.display_command()))?;
    ensure_success(
        &format!("{action} UFW rule {}", rule.display_command()),
        &output,
    )
}

fn command() -> Result<Command> {
    const PATHS: &[&str] = &["/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw"];
    let path = PATHS
        .iter()
        .find(|path| Path::new(path).is_file())
        .context(
            "ufw executable not found in a system path (set ufw.manage=false or install ufw)",
        )?;
    Ok(Command::new(path))
}

fn ensure_success(action: &str, output: &Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    bail!("{action} failed: {}{}", stdout.trim(), stderr.trim())
}

fn build_plan(desired: Vec<Rule>, observed: Vec<Rule>) -> Plan {
    let desired_set: HashSet<_> = desired.iter().cloned().collect();
    let observed_set: HashSet<_> = observed.iter().cloned().collect();
    Plan {
        add: desired
            .into_iter()
            .filter(|rule| !observed_set.contains(rule))
            .collect(),
        delete: observed
            .into_iter()
            .filter(|rule| !desired_set.contains(rule))
            .collect(),
        kept: desired_set.intersection(&observed_set).count(),
    }
}

fn parse_added(output: &str) -> Vec<Rule> {
    output.lines().filter_map(parse_added_line).collect()
}

fn parse_added_line(line: &str) -> Option<Rule> {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 11 || fields[0..3] != ["ufw", "route", "allow"] {
        return None;
    }

    let mut protocol = None;
    let mut target_ip = None;
    let mut target_port = None;
    let mut comment = None;
    for pair in fields[3..].chunks_exact(2) {
        match pair[0] {
            "proto" => protocol = Some(pair[1]),
            "to" => target_ip = Some(pair[1]),
            "port" => target_port = pair[1].parse().ok(),
            "comment" => comment = Some(pair[1].trim_matches(['\'', '"'])),
            _ => return None,
        }
    }
    let rule = Rule {
        protocol: protocol?.to_string(),
        target_ip: target_ip?.to_string(),
        target_port: target_port?,
    };
    (comment? == rule.comment()).then_some(rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mapping, Protocol};

    fn rule(port: u16) -> Rule {
        Rule {
            protocol: "tcp".into(),
            target_ip: "192.0.2.10".into(),
            target_port: port,
        }
    }

    #[test]
    fn parses_only_owned_route_rules() {
        let owned = rule(80);
        let output = format!(
            "Added user rules (see 'ufw status' for running firewall):\n\
             ufw allow 22/tcp\n\
             {}\n\
             ufw route allow proto udp to 192.0.2.11 port 53 comment 'other'\n",
            owned.display_command()
        );
        assert_eq!(parse_added(&output), vec![owned]);
    }

    #[test]
    fn plans_add_delete_and_keep() {
        let plan = build_plan(vec![rule(80), rule(81)], vec![rule(80), rule(82)]);
        assert_eq!(plan.kept, 1);
        assert_eq!(plan.add, vec![rule(81)]);
        assert_eq!(plan.delete, vec![rule(82)]);
    }

    #[test]
    fn desired_rules_include_only_enabled_mappings() {
        let mut cfg = Config::default();
        cfg.mappings.push(Mapping {
            id: "web".into(),
            name: String::new(),
            protocol: Protocol::Tcp,
            listen_ip: "0.0.0.0".into(),
            listen_port: 8080,
            target_ip: "192.0.2.10".into(),
            target_port: 80,
            enabled: true,
            masquerade: true,
            description: String::new(),
        });
        let mut disabled = cfg.mappings[0].clone();
        disabled.id = "off".into();
        disabled.enabled = false;
        cfg.mappings.push(disabled);
        assert_eq!(desired_rules(&cfg), vec![rule(80)]);
    }

    #[test]
    fn desired_rules_deduplicate_shared_targets() {
        let mut cfg = Config::default();
        let mapping = Mapping {
            id: "a".into(),
            name: String::new(),
            protocol: Protocol::Tcp,
            listen_ip: "0.0.0.0".into(),
            listen_port: 8080,
            target_ip: "192.0.2.10".into(),
            target_port: 80,
            enabled: true,
            masquerade: true,
            description: String::new(),
        };
        cfg.mappings.push(mapping.clone());
        let mut shared = mapping;
        shared.id = "b".into();
        shared.listen_port = 8081;
        cfg.mappings.push(shared);
        assert_eq!(desired_rules(&cfg), vec![rule(80)]);
    }
}
