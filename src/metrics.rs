//! Prometheus exporter (liveness only).
//!
//! Exposes `nporter_up` and `nporter_mappings_configured`. Per-rule traffic
//! byte/packet metrics were removed: on cloud hosts with flow offload the
//! forward-hook counters only see new-connection SYNs, so byte stats are
//! unreliable. The HTTP endpoint is a minimal hand-rolled responder on
//! `std::net::TcpListener` (one internal endpoint) — no HTTP-server dependency.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use anyhow::{Context, Result};
use prometheus::{Encoder, Gauge, Opts, Registry, TextEncoder};

use crate::model::Config;

struct Inner {
    mappings: Gauge,
}

/// Handle to publish metrics. `None` when Prometheus is disabled (no-op).
#[derive(Clone)]
pub struct Metrics(Option<Arc<Inner>>);

fn gauge(name: &str, help: &str) -> Result<Gauge> {
    Gauge::with_opts(Opts::new(name, help).namespace("nporter")).map_err(Into::into)
}

pub fn start(cfg: &Config) -> Result<Metrics> {
    if !cfg.prometheus.enabled {
        return Ok(Metrics(None));
    }

    let registry = Registry::new();
    let up = gauge("up", "Whether the NPorter daemon is running.")?;
    let mappings = gauge(
        "mappings_configured",
        "Number of mappings loaded by the daemon.",
    )?;
    registry.register(Box::new(up.clone()))?;
    registry.register(Box::new(mappings.clone()))?;
    up.set(1.0);

    let listener = TcpListener::bind(&cfg.prometheus.listen_address)
        .with_context(|| format!("binding prometheus on {}", cfg.prometheus.listen_address))?;
    println!(
        "prometheus: listening on {}{}",
        cfg.prometheus.listen_address, cfg.prometheus.path
    );

    let path = cfg.prometheus.path.clone();
    std::thread::spawn(move || serve(listener, path, registry));

    Ok(Metrics(Some(Arc::new(Inner { mappings }))))
}

impl Metrics {
    pub fn set_mappings(&self, n: usize) {
        if let Some(i) = &self.0 {
            i.mappings.set(n as f64);
        }
    }
}

fn serve(listener: TcpListener, path: String, registry: Registry) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        // Bound how long one client can hold the (single-threaded) loop, so a
        // slow/idle connection cannot stall metric scrapes (Slowloris).
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let target = req
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .map(|t| t.split('?').next().unwrap_or(t))
            .unwrap_or("");

        if target == path {
            let mut body = Vec::new();
            let encoder = TextEncoder::new();
            let _ = encoder.encode(&registry.gather(), &mut body);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                encoder.format_type(),
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
        } else {
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    }
}
