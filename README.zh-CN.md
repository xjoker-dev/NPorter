# NPorter 中文文档

[English README](README.md)

NPorter 是一个 Rust 编写的 nftables 端口转发管理器，提供 CLI、终端 TUI、目标延迟探测
和可选 Prometheus 存活指标。运行时直接通过 netlink 管理 nftables 规则，不依赖 `nft`
命令行二进制。

## 特性

- CLI 全量管理：`list/add/set/enable/disable/masquerade/delete/config/check/plan/apply/status/probe/daemon/tui`。
- 基于 ratatui 的终端 TUI，可交互管理规则。
- `inet` 双栈：同一张表支持 IPv4 / IPv6 mapping。
- 增量 apply：字段未变的规则会原地保留，避免每次配置变更都重建规则。
- 目标探测：TCP 使用握手 RTT，UDP 使用 ICMP ping 探测目标主机。
- 可选 Prometheus 存活指标：`nporter_up`、`nporter_mappings_configured`。默认关闭，默认只监听 `127.0.0.1`。

> NPorter 不导出字节级/包级流量统计。部分云主机/VPC 会让 established 流绕过 guest
> forward hook，导致 nftables forward counter 不能准确反映真实流量。NPorter 保留
> 存活和可达性检查，但不宣称提供精确字节统计。

## 配置

配置文件为 TOML。默认路径是二进制同目录的 `nporter.toml`；安装后即
`/etc/nporter/nporter.toml`。

示例：

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

安全默认值：

- 安装脚本会把 `/etc/nporter` 创建为 `0750`。
- 配置文件权限强制为 `0600`。
- 安装脚本拒绝 symlink 配置文件。
- Prometheus 默认关闭；启用时建议保持本地监听，公网访问请通过 SSH 转发、VPN 或可信反向代理保护。

## 构建

本地开发：

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

Linux netlink 后端需要 Linux 内核头和 libclang。在 macOS 或非 Linux 主机上，使用容器脚本：

```bash
scripts/linux-check.sh build
scripts/linux-check.sh test
scripts/build-release.sh
```

`scripts/build-release.sh` 输出 Linux amd64 和 arm64 二进制：

```text
target-linux/x86_64-unknown-linux-musl/release/nporter
target-linux/aarch64-unknown-linux-musl/release/nporter
```

可通过 `RUST_IMAGE` 覆盖 Docker 镜像：

```bash
RUST_IMAGE=rust:1.88 scripts/build-release.sh
```

## 自动化构建

GitHub Actions 会在 push 和 pull request 时自动运行：

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `cargo audit`
- Linux `x86_64-unknown-linux-musl` 和 `aarch64-unknown-linux-musl` release 构建
- 上传 `nporter-linux-amd64` 和 `nporter-linux-arm64` workflow artifact

## 版本发布

版本发布通过 Git tag 控制。普通分支 push 只运行 CI；推送 `v*` tag 时会创建或更新
GitHub Release 并上传：

- `nporter-linux-amd64.tar.gz`
- `nporter-linux-amd64.tar.gz.sha256`
- `nporter-linux-arm64.tar.gz`
- `nporter-linux-arm64.tar.gz.sha256`

打 tag 前，确保 `src/cli.rs` 中的 `VERSION` 与 tag 去掉开头 `v` 后一致。版本格式为
`YYYYMMDD.N`：日期使用发布日期，同一天多次发布时递增 `N`。release workflow 会拒绝
版本不一致的 tag。

```bash
# 例如：VERSION 必须是 "20260607.1"
git tag v20260607.1
git push origin v20260607.1
```

## 安装

release 二进制为静态链接，运行期系统包依赖很少：

- Linux 主机，需要内核支持 nftables / netfilter NAT。
- `apply` 和 `daemon` 需要 root 权限，或等价的 `CAP_NET_ADMIN`。
- systemd 是可选项，仅安装 `nporter.service` 时需要。
- NPorter 运行时不需要安装 `nft` 命令行包。

**一键安装**（自动识别 amd64 / arm64）：

```bash
curl -fsSL https://raw.githubusercontent.com/xjoker-dev/NPorter/master/get.sh | sudo bash
```

安装后立即启用并启动服务：

```bash
curl -fsSL https://raw.githubusercontent.com/xjoker-dev/NPorter/master/get.sh | sudo bash -s -- --now
```

也可手动下载 release tarball，解压后以 root 运行安装脚本：

```bash
tar -xzf nporter-linux-amd64.tar.gz
sudo ./install.sh
```

安装脚本会：

- 安装二进制到 `/etc/nporter/nporter`；
- 创建 `/usr/local/bin/nporter` symlink；
- 在缺失时创建 `/etc/nporter/nporter.toml`；
- 如果存在 `systemd/nporter.service`，安装 systemd unit；
- 默认不会自动 enable 或启动服务，除非显式传入选项。

启用服务前先检查配置：

```bash
sudo nporter --config /etc/nporter/nporter.toml check
sudo nporter --config /etc/nporter/nporter.toml plan
sudo systemctl enable --now nporter
```

检查配置后，如果希望一步安装并启用服务：

```bash
sudo ./install.sh --now
```

安装脚本选项：

```text
--enable       设置 nporter.service 开机自启。
--start        安装后立即启动 nporter.service。
--now          设置开机自启并立即启动。
--no-systemd   不安装 systemd unit。
```

## Daemon 与 systemd

`nporter daemon` 是 systemd unit 使用的常驻进程。服务启动时，
`systemd/nporter.service` 会先运行 `nporter apply` 对齐 nftables 规则，然后启动
`nporter daemon`。daemon 负责保持进程常驻，并在启用 Prometheus 时提供 exporter。

常用命令：

```bash
sudo systemctl enable --now nporter
sudo systemctl status nporter
sudo journalctl -u nporter -f
sudo systemctl restart nporter
sudo systemctl stop nporter
```

修改 `/etc/nporter/nporter.toml` 后，重启服务以加载新配置并重新 apply：

```bash
sudo nporter --config /etc/nporter/nporter.toml check
sudo systemctl restart nporter
```

启用 Prometheus 存活指标：

```bash
sudo nporter --config /etc/nporter/nporter.toml config \
  --prometheus-enabled true \
  --prometheus-listen-address 127.0.0.1:9090 \
  --prometheus-path /metrics

sudo systemctl restart nporter
curl http://127.0.0.1:9090/metrics
```

exporter 只暴露 `nporter_up` 和 `nporter_mappings_configured`。除非通过 SSH 转发、
VPN 或可信反向代理保护访问，否则建议保持 localhost 监听。

## 使用

添加并应用一个 mapping：

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

探测目标可达性：

```bash
nporter probe
nporter probe web
```

运行 TUI：

```bash
sudo nporter tui
```

常用 TUI 按键：

```text
a        添加 mapping
e/Enter  编辑 mapping
Space    启用/禁用
m        切换 masquerade
d        删除 mapping
w        保存配置
A        保存并应用
p        探测选中目标
P        探测全部目标
h/?      帮助
q        退出
```

## 运维注意事项

- 通过 NPorter 管理 NPorter 生成的规则，避免直接用原生 `nft` 修改这些规则。
- 当 `enable_ip_forward = true` 时，`apply` 会启用 IPv4/IPv6 forwarding。
- systemd unit 需要 `CAP_NET_ADMIN`，同时已通过 capability 和读写路径限制做沙箱收敛。
- 示例应使用文档网段，不要提交真实服务器 IP、内网拓扑、凭据或运维邮箱。

## 许可证

MIT.
