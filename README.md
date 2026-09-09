# server-kit

A networking toolkit for Debian VPS: AmneziaWG, VLESS, subscriptions, and a private web dashboard.

面向 Debian VPS 的网络工具集：AmneziaWG、VLESS、订阅管理与内网控制面板。

[English](#english) · [简体中文](#简体中文)

## English

### Before you start

- **Debian 12/13, amd64**, systemd, root access, and a kernel that supports AmneziaWG.
- Keep your SSH session open and your provider’s recovery console available.
- Allow your SSH port, **UDP 443**, and the backup AWG UDP port shown during setup in the cloud firewall. Open other ports as needed; **do not expose dashboard port 9080 publicly**.

The CLI and dashboard currently use Chinese. Run the following commands on the VPS as root unless stated otherwise.

### 1. Install

```bash
apt-get update
apt-get install -y git ca-certificates python3
git clone https://github.com/je00/server-kit.git /root/server-kit
cd /root/server-kit
bash install-server-kit.sh install
server-kit preflight
server-kit init
```

Follow the prompts to set the administrator account, password, and dashboard port (default: `9080`). Initialization installs AWG if needed and creates the private dashboard; it does not change SSH settings or apply the host firewall policy. If a kernel reboot is requested, ensure recovery access, reboot, then rerun initialization.

### 2. Open the dashboard

In a **new terminal on your computer**, replace `YOUR_VPS_IP` and `SSH_PORT` with your working SSH connection details:

```bash
ssh -N -L 127.0.0.1:9080:10.20.0.1:9080 -p SSH_PORT root@YOUR_VPS_IP
```

Keep the terminal open. Visit **http://127.0.0.1:9080** and sign in. If setup printed a different AWG address or dashboard port, use those values instead.

### 3. Connect your first device

1. Open **内网节点** (Network nodes) and add a regular AWG node.
2. Save the browser-generated configuration or scan its QR code with an AmneziaWG-compatible client. Keep it safe: the VPS does not retain the client private key.
3. Connect AWG and verify **http://10.20.0.1:9080** opens directly before closing the temporary SSH tunnel.

### 4. Add what you need

Use the dashboard’s deployment wizard to install VLESS and Clash subscriptions; Mosh and file hosting are optional. Subscription setup requires an upstream subscription URL and an outbound proxy configuration.

- **IP changes:** configure a stable hostname and DNSPod or DuckDNS under **域名管理** (Domain management). DDNS attempts an update shortly after boot; recovery still depends on network readiness and client DNS caches.
- **Exit-consistent DNS:** resolve business domains through their selected proxy exit. See the [operations guide](docs/operations.md#出口一致-dns); refresh client subscriptions after enabling it.
- **Security:** verify a second working connection before confirming SSH or firewall changes. Create an encrypted backup and store its recovery password separately.

### Update and troubleshoot

Run updates from the freshly pulled source, not the global command pointing at the installed release:

```bash
cd /root/server-kit
git pull --ff-only
bash ./server-kit update-web
```

Web updates check health and roll back on failure. They do not change the administrator password, AWG, SSH, or firewall configuration.

```bash
server-kit status                # Dashboard status
server-kit-manager.sh status     # Managed services
server-kit-manager.sh audit      # Configuration checks
server-kit recovery              # Recovery menu via SSH/provider console
```

Dashboard unreachable? Check the SSH tunnel, address, and port. AWG unreachable? Check cloud firewall UDP rules and client endpoints. Do not start by disabling the firewall or restarting every service.

## 简体中文

### 开始之前

- 准备 **Debian 12/13、amd64** VPS，运行 systemd，具备 root 权限及支持 AmneziaWG 的内核。
- 保留当前 SSH 连接，并确认能使用服务商的救援控制台。
- 云防火墙放行现用 SSH 端口、**UDP 443** 和安装时显示的 AWG 备用 UDP 端口。其他服务按需开放，**不要向公网开放面板端口 9080**。

除特别说明外，以下命令均在 VPS 上以 root 执行。

### 1. 安装

```bash
apt-get update
apt-get install -y git ca-certificates python3
git clone https://github.com/je00/server-kit.git /root/server-kit
cd /root/server-kit
bash install-server-kit.sh install
server-kit preflight
server-kit init
```

按提示设置管理员账号、密码和面板端口（默认 `9080`）。初始化会按需安装 AWG 并建立内网面板，不修改 SSH 设置，也不应用主机防火墙策略。如提示需要重启内核，确认有恢复入口后重启，再运行初始化。

### 2. 打开面板

在**自己电脑上另开终端**，将 `YOUR_VPS_IP` 和 `SSH_PORT` 替换为当前可用的 SSH 地址与端口：

```bash
ssh -N -L 127.0.0.1:9080:10.20.0.1:9080 -p SSH_PORT root@YOUR_VPS_IP
```

保持终端运行，打开 **http://127.0.0.1:9080** 并登录。若初始化输出了不同的 AWG 地址或面板端口，请按实际值替换。

### 3. 连接第一台设备

1. 进入 **内网节点**，新增普通 AWG 节点。
2. 保存浏览器生成的配置，或用兼容 AmneziaWG 的客户端扫码导入。妥善保管配置：VPS 不保存客户端私钥。
3. 连接 AWG，确认可直接打开 **http://10.20.0.1:9080**，再关闭临时 SSH 隧道。

### 4. 按需配置

通过面板的首次部署向导安装 VLESS 和 Clash 订阅；Mosh、文件发布为可选项。安装订阅服务需准备机场订阅链接和出口代理配置。

- **应对 VPS 换 IP：**在 **域名管理** 配置稳定域名及 DNSPod 或 DuckDNS。开机后会尽快尝试更新 DDNS，但恢复仍受网络就绪时间和客户端 DNS 缓存影响。
- **出口一致 DNS：**让业务域名通过指定代理出口解析。操作见[运维指南](docs/operations.md#出口一致-dns)，启用后需更新客户端订阅。
- **安全加固：**修改 SSH 或防火墙后，先从另一条连接验证，再确认生效。创建加密备份，并单独保存恢复口令。

### 更新与排障

从刚拉取的源码运行更新，不要调用仍指向已安装版本的全局命令：

```bash
cd /root/server-kit
git pull --ff-only
bash ./server-kit update-web
```

管理网站更新会检查健康状态，失败自动回退；不修改管理员密码、AWG、SSH 或防火墙配置。

```bash
server-kit status                # 查看面板状态
server-kit-manager.sh status     # 查看托管服务
server-kit-manager.sh audit      # 检查配置
server-kit recovery              # 通过 SSH / 救援控制台进入恢复菜单
```

面板打不开，先检查 SSH 隧道、地址和端口；AWG 连不上，先检查云防火墙 UDP 放行和客户端入口。不要一上来关闭防火墙或重启全部服务。

## Documentation / 详细文档

- [Operations guide / 运维指南（中文）](docs/operations.md)
- [IP-change recovery / 公网 IP 变更恢复（中文）](docs/public-ip-change-runbook.md)
- [Security architecture / 管理平面安全设计（中文）](docs/management-plane-design.md)
- [Local key generator / 本地密钥生成器（中文）](browser_extension/README.md)

Never commit credentials, generated subscriptions, or backups. Example domains and addresses are placeholders.

请勿提交凭据、生成的订阅或备份；示例域名与地址须替换为自己的配置。
