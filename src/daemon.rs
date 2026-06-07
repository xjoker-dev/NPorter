//! Liveness daemon: serves the Prometheus exporter (if enabled) and stays
//! resident under systemd. Traffic-byte sampling was removed — established-flow
//! packets are offloaded past the nftables forward hook on some cloud hosts
//! on some cloud/VPC hosts, making byte counts unreliable there.

use std::time::Duration;

use anyhow::Result;

use crate::model::Config;

pub fn run(cfg: &Config) -> Result<()> {
    let prom = crate::metrics::start(cfg)?;
    prom.set_mappings(cfg.mappings.len());
    println!("daemon: started");
    // Nothing to sample; the exporter (if enabled) runs in its own thread.
    // Stay alive until the service is stopped (SIGTERM).
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
