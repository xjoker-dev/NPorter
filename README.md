# NPorter

[中文文档](README.zh-CN.md)

NPorter is a Rust-based nftables port-forwarding manager. It provides a CLI,
a terminal UI, target latency probes, and an optional Prometheus liveness
endpoint. Rules are applied through nftables netlink via `rustables`; the
runtime path does not shell out to the `nft` binary.

## Features

- CLI commands: `list`, `add`, `set`, `enable`, `disable`, `masquerade`,
  `delete`, `config`, `check`, `plan`, `apply`, `status`, `probe`, `daemon`,
  and `tui`.
- Terminal UI built with ratatui for interactive rule management.
- `inet` dual-stack support for IPv4 and IPv6 mappings in one table.
- Incremental apply: unchanged rules are kept in place, so counters are not
  reset by every config edit.
- Target probes: TCP mappings use TCP handshake RTT; UDP mappings use ICMP
  ping to the target host.
- Optional Prometheus liveness endpoint: `nporter_up` and
  `nporter_mappings_configured`. It is disabled by default and binds to
  `127.0.0.1`.

> Traffic byte/packet metrics are intentionally not exported. Some cloud/VPC
> hosts offload established flows around the guest forward hook, so nftables
> forward counters can under-report real traffic. NPorter keeps liveness and
> reachability checks, but does not claim byte-accurate accounting.

## Configuration

Configuration is TOML. The default config path is `nporter.toml` next to the
binary; after installation this is `/etc/nporter/nporter.toml`.

Sample:

```toml
[nftables]
family = "inet"
table_name = "nporter"
enable_ip_forward = true
default_masquerade = true

[prometheus]
enabled = false
listen_address = "127.0.0.1:9090"
path = "/metrics"

[[mappings]]
id = "example-web"
name = "Example web service"
protocol = "tcp"
listen_ip = "127.0.0.1"
listen_port = 8080
target_ip = "192.0.2.10"
target_port = 80
enabled = false
masquerade = true
```

Security defaults:

- The installer creates `/etc/nporter` as `0750`.
- The config file is forced to `0600`.
- Symlinked configs are refused by the installer.
- Prometheus is disabled by default and should stay local unless protected by
  SSH forwarding, VPN, or a trusted reverse proxy.

## Build

Local development:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

Linux netlink builds need Linux headers and libclang. From macOS or other
non-Linux hosts, use the container helpers:

```bash
scripts/linux-check.sh build
scripts/linux-check.sh test
scripts/build-release.sh
```

`scripts/build-release.sh` produces Linux amd64 and arm64 binaries:

```text
target-linux/x86_64-unknown-linux-musl/release/nporter
target-linux/aarch64-unknown-linux-musl/release/nporter
```

`RUST_IMAGE` can override the Docker image:

```bash
RUST_IMAGE=rust:1.88 scripts/build-release.sh
```

## CI

GitHub Actions runs on every push and pull request:

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `cargo audit`
- Linux `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` release builds
- Uploads the `nporter-linux-amd64` and `nporter-linux-arm64` workflow artifacts

## Release

Releases are controlled by Git tags. Normal branch pushes only run CI; pushing
a `v*` tag creates or updates a GitHub Release and uploads:

- `nporter-linux-amd64.tar.gz`
- `nporter-linux-amd64.tar.gz.sha256`
- `nporter-linux-arm64.tar.gz`
- `nporter-linux-arm64.tar.gz.sha256`

Before tagging, make sure `src/cli.rs` `VERSION` matches the tag without the
leading `v`. The version format is `YYYYMMDD.N`: use the release date, and
increment `N` for additional releases on the same date. The release workflow
rejects mismatches.

```bash
# Example: VERSION must be "20260607.1"
git tag v20260607.1
git push origin v20260607.1
```

## Install

Release binaries are statically linked. Runtime package dependencies are minimal:

- Linux with nftables/netfilter NAT kernel support.
- root privileges, or equivalent `CAP_NET_ADMIN`, for `apply` and `daemon`.
- systemd is optional and only needed when installing `nporter.service`.
- The `nft` CLI package is not required by NPorter at runtime.

**One-command install** (detects amd64 / arm64 automatically):

```bash
curl -fsSL https://raw.githubusercontent.com/xjoker-dev/NPorter/master/get.sh | sudo bash
```

To enable and start the service immediately after install:

```bash
curl -fsSL https://raw.githubusercontent.com/xjoker-dev/NPorter/master/get.sh | sudo bash -s -- --now
```

Alternatively, download the release tarball manually, extract it, and run the
installer as root:

```bash
tar -xzf nporter-linux-amd64.tar.gz
sudo ./install.sh
```

The installer:

- installs the binary to `/etc/nporter/nporter`;
- creates `/usr/local/bin/nporter` as a symlink;
- creates `/etc/nporter/nporter.toml` when missing;
- installs `systemd/nporter.service` when the unit file is present;
- does not enable or start the service automatically unless requested.

Review the config before enabling the service:

```bash
sudo nporter --config /etc/nporter/nporter.toml check
sudo nporter --config /etc/nporter/nporter.toml plan
sudo systemctl enable --now nporter
```

For one-command service setup after reviewing the config, run:

```bash
sudo ./install.sh --now
```

Installer options:

```text
--enable       Enable nporter.service at boot.
--start        Start nporter.service after installation.
--now          Enable and start nporter.service.
--no-systemd   Do not install the systemd unit.
```

## Daemon and systemd

`nporter daemon` is the resident process used by the systemd unit. On service
start, `systemd/nporter.service` first runs `nporter apply` to reconcile the
nftables rules, then starts `nporter daemon`. The daemon keeps the process alive
and serves the Prometheus exporter when it is enabled.

Common commands:

```bash
sudo systemctl enable --now nporter
sudo systemctl status nporter
sudo journalctl -u nporter -f
sudo systemctl restart nporter
sudo systemctl stop nporter
```

After changing `/etc/nporter/nporter.toml`, restart the service so the new
config is loaded and the rules are re-applied:

```bash
sudo nporter --config /etc/nporter/nporter.toml check
sudo systemctl restart nporter
```

Enable the Prometheus liveness endpoint:

```bash
sudo nporter --config /etc/nporter/nporter.toml config \
  --prometheus-enabled true \
  --prometheus-listen-address 127.0.0.1:9090 \
  --prometheus-path /metrics

sudo systemctl restart nporter
curl http://127.0.0.1:9090/metrics
```

The exporter exposes `nporter_up` and `nporter_mappings_configured` only. Keep
the listener on localhost unless access is protected by SSH forwarding, VPN, or
a trusted reverse proxy.

## Usage

Add and apply a mapping:

```bash
sudo nporter add web \
  --listen-ip 0.0.0.0 \
  --listen-port 8080 \
  --target-ip 192.0.2.10 \
  --target-port 80

sudo nporter plan
sudo nporter apply
sudo nporter status
```

Probe targets:

```bash
nporter probe
nporter probe web
```

Run the TUI:

```bash
sudo nporter tui
```

Common TUI keys:

```text
a        add mapping
e/Enter  edit mapping
Space    enable/disable
m        toggle masquerade
d        delete mapping
w        save config
A        save and apply
p        probe selected target
P        probe all targets
h/?      help
q        quit
```

## Operational Notes

- Manage NPorter-owned rules through NPorter. Avoid editing its generated
  rules with raw `nft` commands.
- `apply` may enable IPv4/IPv6 forwarding when `enable_ip_forward = true`.
- The systemd unit intentionally needs `CAP_NET_ADMIN`; it is sandboxed with
  a restricted capability set and read/write paths.
- Use documentation IP ranges in examples. Do not commit real server IPs,
  private topology, credentials, or operator emails.

## License

MIT.
