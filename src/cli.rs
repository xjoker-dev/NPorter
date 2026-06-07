//! Command-line interface.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::{ArgAction, Parser, Subcommand};

use crate::config;
use crate::model::{Config, Mapping, Protocol};

/// Date-based version following Yuki's `YYYYMMDD.N` scheme. Bumped manually per
/// release. (Cargo's package version stays semver because this form is not.)
pub const VERSION: &str = "20260607.1";

#[derive(Parser)]
#[command(name = "nporter", version = VERSION, about = "nftables port-forwarding manager")]
pub struct Cli {
    /// Config file path (defaults to nporter.toml next to the binary).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List configured mappings.
    List,
    /// Add a new mapping.
    Add(AddArgs),
    /// Update fields of an existing mapping (only the flags you pass change).
    Set(SetArgs),
    /// Enable a mapping.
    Enable { id: String },
    /// Disable a mapping.
    Disable { id: String },
    /// Set masquerade on a mapping.
    Masquerade {
        id: String,
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        enabled: bool,
    },
    /// Delete a mapping.
    Delete { id: String },
    /// Show or change daemon/prometheus config.
    Config(ConfigArgs),
    /// Validate config and the generated ruleset.
    Check,
    /// Print the desired ruleset without applying it.
    Plan,
    /// Apply the desired ruleset to the kernel.
    Apply,
    /// Show runtime status.
    Status,
    /// Measure latency to mapping target(s) (TCP handshake / ICMP ping).
    Probe { id: Option<String> },
    /// Run the resident daemon (serves the Prometheus exporter if enabled).
    Daemon,
    /// Launch the interactive TUI.
    Tui,
}

#[derive(clap::Args)]
struct AddArgs {
    /// Mapping id (unique).
    id: String,
    #[arg(long, default_value = "")]
    name: String,
    #[arg(long, value_parser = parse_proto, default_value = "tcp")]
    proto: Protocol,
    #[arg(long = "listen-ip", default_value = "0.0.0.0")]
    listen_ip: String,
    #[arg(long = "listen-port")]
    listen_port: u16,
    #[arg(long = "target-ip")]
    target_ip: String,
    #[arg(long = "target-port")]
    target_port: u16,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    enabled: bool,
    /// Masquerade (SNAT) for this mapping. Defaults to nftables.default_masquerade.
    #[arg(long)]
    masquerade: Option<bool>,
    #[arg(long, default_value = "")]
    description: String,
}

#[derive(clap::Args)]
struct SetArgs {
    /// Mapping id to update.
    id: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long, value_parser = parse_proto)]
    proto: Option<Protocol>,
    #[arg(long = "listen-ip")]
    listen_ip: Option<String>,
    #[arg(long = "listen-port")]
    listen_port: Option<u16>,
    #[arg(long = "target-ip")]
    target_ip: Option<String>,
    #[arg(long = "target-port")]
    target_port: Option<u16>,
    #[arg(long)]
    enabled: Option<bool>,
    #[arg(long)]
    masquerade: Option<bool>,
    #[arg(long)]
    description: Option<String>,
}

#[derive(clap::Args)]
struct ConfigArgs {
    #[arg(long = "prometheus-enabled")]
    prometheus_enabled: Option<bool>,
    #[arg(long = "prometheus-listen-address")]
    prometheus_listen_address: Option<String>,
    #[arg(long = "prometheus-path")]
    prometheus_path: Option<String>,
}

fn parse_proto(s: &str) -> Result<Protocol, String> {
    s.parse()
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.config {
        Some(p) => p,
        None => default_config_path()?,
    };

    match cli.command {
        Commands::List => cmd_list(&path),
        Commands::Add(a) => cmd_add(&path, a),
        Commands::Set(a) => cmd_set(&path, a),
        Commands::Enable { id } => cmd_set_enabled(&path, &id, true),
        Commands::Disable { id } => cmd_set_enabled(&path, &id, false),
        Commands::Masquerade { id, enabled } => cmd_masquerade(&path, &id, enabled),
        Commands::Delete { id } => cmd_delete(&path, &id),
        Commands::Config(a) => cmd_config(&path, a),
        Commands::Check => cmd_check(&path),
        Commands::Plan => cmd_plan(&path),
        Commands::Apply => cmd_apply(&path),
        Commands::Status => cmd_status(&path),
        Commands::Probe { id } => cmd_probe(&path, id),
        Commands::Daemon => cmd_daemon(&path),
        Commands::Tui => crate::tui::run(path),
    }
}

fn default_config_path() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let mut dir = exe.parent().map(PathBuf::from).unwrap_or_default();
    // During `cargo run`/tests the binary lives under target/, which is not
    // where the user's config is — fall back to the current directory.
    if dir.components().any(|c| c.as_os_str() == "target") {
        dir = std::env::current_dir()?;
    }
    Ok(dir.join("nporter.toml"))
}

fn load(path: &Path) -> Result<Config> {
    let (cfg, created) = config::load_or_create(path)?;
    if created {
        println!("created default config: {}", path.display());
    }
    Ok(cfg)
}

fn cmd_list(path: &Path) -> Result<()> {
    let cfg = load(path)?;
    if cfg.mappings.is_empty() {
        println!("no mappings");
        return Ok(());
    }
    println!("ID\tPROTO\tLISTEN\tTARGET\tSTATE\tMASQ");
    for m in &cfg.mappings {
        let state = if m.enabled { "enabled" } else { "disabled" };
        println!(
            "{}\t{}\t{}:{}\t{}:{}\t{}\t{}",
            m.id,
            m.protocol,
            m.listen_ip,
            m.listen_port,
            m.target_ip,
            m.target_port,
            state,
            m.masquerade
        );
    }
    Ok(())
}

fn cmd_add(path: &Path, a: AddArgs) -> Result<()> {
    let mut cfg = load(path)?;
    if cfg.mappings.iter().any(|m| m.id == a.id) {
        bail!("mapping id already exists: {}", a.id);
    }
    let masquerade = a.masquerade.unwrap_or(cfg.nftables.default_masquerade);
    cfg.mappings.push(Mapping {
        id: a.id.clone(),
        name: a.name,
        protocol: a.proto,
        listen_ip: a.listen_ip,
        listen_port: a.listen_port,
        target_ip: a.target_ip,
        target_port: a.target_port,
        enabled: a.enabled,
        masquerade,
        description: a.description,
    });
    config::save(path, &cfg)?;
    println!("added: {}", a.id);
    Ok(())
}

fn cmd_set(path: &Path, a: SetArgs) -> Result<()> {
    let mut cfg = load(path)?;
    let idx = mapping_index(&cfg, &a.id)?;
    let m = &mut cfg.mappings[idx];
    if let Some(v) = a.name {
        m.name = v;
    }
    if let Some(v) = a.proto {
        m.protocol = v;
    }
    if let Some(v) = a.listen_ip {
        m.listen_ip = v;
    }
    if let Some(v) = a.listen_port {
        m.listen_port = v;
    }
    if let Some(v) = a.target_ip {
        m.target_ip = v;
    }
    if let Some(v) = a.target_port {
        m.target_port = v;
    }
    if let Some(v) = a.enabled {
        m.enabled = v;
    }
    if let Some(v) = a.masquerade {
        m.masquerade = v;
    }
    if let Some(v) = a.description {
        m.description = v;
    }
    config::save(path, &cfg)?;
    println!("updated: {}", a.id);
    Ok(())
}

fn cmd_set_enabled(path: &Path, id: &str, enabled: bool) -> Result<()> {
    let mut cfg = load(path)?;
    let idx = mapping_index(&cfg, id)?;
    cfg.mappings[idx].enabled = enabled;
    config::save(path, &cfg)?;
    println!("updated: {id} enabled={enabled}");
    Ok(())
}

fn cmd_masquerade(path: &Path, id: &str, enabled: bool) -> Result<()> {
    let mut cfg = load(path)?;
    let idx = mapping_index(&cfg, id)?;
    cfg.mappings[idx].masquerade = enabled;
    config::save(path, &cfg)?;
    println!("updated: {id} masquerade={enabled}");
    Ok(())
}

fn cmd_delete(path: &Path, id: &str) -> Result<()> {
    let mut cfg = load(path)?;
    let before = cfg.mappings.len();
    cfg.mappings.retain(|m| m.id != id);
    if cfg.mappings.len() == before {
        bail!("mapping id not found: {id}");
    }
    config::save(path, &cfg)?;
    println!("deleted: {id}");
    Ok(())
}

fn cmd_config(path: &Path, a: ConfigArgs) -> Result<()> {
    let mut cfg = load(path)?;
    let mut changed = false;
    if let Some(v) = a.prometheus_enabled {
        cfg.prometheus.enabled = v;
        changed = true;
    }
    if let Some(v) = a.prometheus_listen_address {
        cfg.prometheus.listen_address = v;
        changed = true;
    }
    if let Some(v) = a.prometheus_path {
        cfg.prometheus.path = v;
        changed = true;
    }
    if changed {
        config::save(path, &cfg)?;
    }
    println!("prometheus.enabled={}", cfg.prometheus.enabled);
    println!(
        "prometheus.listen_address={}",
        cfg.prometheus.listen_address
    );
    println!("prometheus.path={}", cfg.prometheus.path);
    Ok(())
}

fn cmd_check(path: &Path) -> Result<()> {
    let cfg = load(path)?;
    // load() already validated; build the rules to surface any id/family issues.
    let rules = crate::nft::desired_rules(&cfg)?;
    println!("config: ok");
    println!("rules: {} (buildable)", rules.len());
    println!("mappings: {}", cfg.mappings.len());
    println!("note: kernel state is checked by `apply` (netlink, atomic)");
    Ok(())
}

fn cmd_plan(path: &Path) -> Result<()> {
    let cfg = load(path)?;
    let rules = crate::nft::desired_rules(&cfg)?;
    println!("desired rules: {}\n", rules.len());
    for r in &rules {
        println!("+ {} {}", r.mapping_id, r.kind);
    }
    println!("\n--- ruleset ---");
    print!("{}", crate::nft::render_ruleset(&cfg)?);
    Ok(())
}

fn cmd_apply(path: &Path) -> Result<()> {
    let cfg = load(path)?;
    let report = crate::nft::apply(&cfg)?;
    println!(
        "apply: ok (added={}, deleted={}, kept={})",
        report.added, report.deleted, report.kept
    );
    Ok(())
}

fn cmd_status(path: &Path) -> Result<()> {
    let cfg = load(path)?;
    println!("mappings: {}", cfg.mappings.len());
    println!("table: {} {}", cfg.nftables.family, cfg.nftables.table_name);
    // Live rules confirm what's actually on the kernel (reconciliation check).
    match crate::nft::observe(&cfg) {
        Ok(rules) => {
            println!("live rules: {}", rules.len());
            for r in &rules {
                println!("  {} {}", r.mapping_id, r.kind);
            }
        }
        Err(e) => println!("live rules: unavailable ({e})"),
    }
    Ok(())
}

fn cmd_daemon(path: &Path) -> Result<()> {
    let cfg = load(path)?;
    crate::daemon::run(&cfg)
}

fn cmd_probe(path: &Path, id: Option<String>) -> Result<()> {
    let cfg = load(path)?;
    let timeout = std::time::Duration::from_secs(2);
    let targets: Vec<_> = match &id {
        Some(want) => cfg.mappings.iter().filter(|m| &m.id == want).collect(),
        None => cfg.mappings.iter().collect(),
    };
    if targets.is_empty() {
        if let Some(want) = id {
            bail!("mapping id not found: {want}");
        }
        println!("no mappings");
        return Ok(());
    }
    for m in targets {
        let r = crate::probe::probe(m, timeout);
        let detail = match (&r.latency, &r.error) {
            (Some(_), _) => format!("{} ({})", r.display(), r.method),
            (None, Some(e)) => format!("unreachable ({}): {}", r.method, e),
            (None, None) => "unreachable".to_string(),
        };
        println!("{}\t{}:{}\t{}", m.id, m.target_ip, m.target_port, detail);
    }
    Ok(())
}

fn mapping_index(cfg: &Config, id: &str) -> Result<usize> {
    cfg.mappings
        .iter()
        .position(|m| m.id == id)
        .ok_or_else(|| anyhow::anyhow!("mapping id not found: {id}"))
}
