# server-kit

**先连通内网，再管理服务。** 用一台 Debian VPS 连接自己的电脑与服务器，在内网网页中管理节点、访问权限和网络服务。

[简体中文](README.md) · [Easy English](README.en.md)

![内网节点与访问权限面板，使用本地模拟数据](docs/images/console-desktop.png)

*截图为本地模拟数据，不包含真实节点、凭据或订阅。网页与命令行目前以中文为主。*

## 能做什么

- **内网互联**：AWG 普通节点可双向访问；按目标、TCP / UDP 和端口范围控制权限，多条规则一起添加。
- **手机访问**：VLESS 节点单向访问已授权的内网服务，默认没有内网权限。
- **统一管理**：部署向导、订阅与代理资源、动态 DNS、任务审计和加密备份。

AWG 节点首次握手确认后默认全内网互通；需要隔离时，先添加必要权限，再撤销“全部”授权。**基础内网管理不需要机场订阅或额外代理出口。**

## 快速部署

### 1. 准备 VPS

需要 **Debian 12 / 13 · amd64 · systemd · root 权限**，以及可编译/加载 AmneziaWG 的内核环境。建议使用全新 VPS；保留现有 SSH 连接和服务商救援控制台。

云安全组及已有主机防火墙需要允许：

| 入口 | 用途 |
| --- | --- |
| 当前 SSH TCP 端口 | 初次安装与恢复 |
| AWG 主 UDP 端口，默认 `443` | 内网连接 |
| 安装时显示的备用 UDP 端口 | 备用入口 |

**不要向公网开放管理端口 `9080`。** 端口以安装输出为准，其他服务按需开放。

### 2. 安装管理面板

在 **VPS 的 root 交互终端**执行：

```bash
apt-get update
apt-get install -y git ca-certificates python3
git clone https://github.com/je00/server-kit.git /root/server-kit
cd /root/server-kit
bash install-server-kit.sh install
server-kit preflight
server-kit init
```

按提示设置超级管理员、密码和面板端口。初始化按需安装 AWG，不自动安装全部可选服务，也不修改 SSH 或应用主机入口防火墙策略；AWG 会配置自身所需的转发和网络规则。

若提示缺少内核头文件、需要重启：先确认恢复入口，按提示重启，再执行 `cd /root/server-kit && bash ./server-kit init`。

### 3. 首次登录：通过 SSH 转发

在**自己电脑上另开终端**，替换 `SSH_PORT` 和 `YOUR_VPS_IP`：

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:9080:10.20.0.1:9080 -p SSH_PORT root@YOUR_VPS_IP
```

终端不输出内容是正常的，保持它运行。打开 [http://127.0.0.1:9080](http://127.0.0.1:9080)，使用刚创建的账号登录。若初始化输出的内网地址或端口不同，请相应替换。

### 4. 添加第一台内网设备

1. 在设备上准备好兼容 **AmneziaWG** 的客户端；打开 **内网节点 → 新增节点**，创建普通 AWG 节点。
2. 按页面提示，在登记前保存或扫码导入浏览器生成的配置。主、备入口都保存，只启用一个；VPS 不保存客户端私钥，丢失后不能找回。
3. **预览并确认登记后，5 分钟内连接**完成首次握手；超时会自动撤销节点，需要重新登记。
4. 等状态变为“已启用”，将首个节点**设为管理入口**。确认能通过 AWG 直接打开 [http://10.20.0.1:9080](http://10.20.0.1:9080)，再关闭临时 SSH 转发。

至此，基础内网管理已可用。添加其他设备时，参考 **部署向导**中的平台步骤；设备自身防火墙仍需放行你要访问的服务。

<details>
<summary>查看手机界面（模拟数据）</summary>

<p><img src="docs/images/console-mobile.png" width="300" alt="手机上的部署向导，使用本地模拟数据"></p>

</details>

## 按需开启，不必一次配完

| 需要 | 去哪里 |
| --- | --- |
| VLESS、Clash 订阅、文件发布、Mosh | 部署向导；首次安装 Clash 需先有 VLESS REALITY，并准备机场链接和出口配置 |
| VPS 更换公网 IP 后恢复 | 域名管理：稳定域名 + DNSPod / DuckDNS；[恢复说明](docs/public-ip-change-runbook.md) |
| 业务 DNS 经指定出口解析 | [出口一致 DNS](docs/operations.md#出口一致-dns)；不保证第三方 IP 定位一致 |
| 收紧 SSH / 防火墙、备份 | 安全事务 / 配置备份；先验证第二条连接，再确认变更 |

SSH / 防火墙等高风险操作可能仅开放预览，须按[安全设计](docs/management-plane-design.md)完成验证后启用。DDNS 恢复受网络就绪和 DNS 缓存影响，不承诺零中断。备份恢复口令需自行保存。

## 更新与排障

在 VPS 上，从**刚拉取的源码**执行更新；全局命令可能仍指向旧版本：

```bash
cd /root/server-kit
git pull --ff-only
bash ./server-kit update-web
```

更新会短暂重启管理服务；内置健康检查失败时尝试回退旧代码，不修改 AWG、SSH 或防火墙配置。代码回退不等于完整数据恢复，更新前先备份并保留 SSH。

```bash
server-kit status                # 管理面板状态
server-kit-manager.sh status     # 托管服务状态
server-kit-manager.sh audit      # 配置检查
server-kit recovery              # 从 SSH / 救援控制台进入恢复菜单
```

面板打不开：先检查 SSH 转发、地址和端口。AWG 连不上：检查 UDP 放行与客户端入口。不要直接关闭防火墙或重启所有服务。

[运维指南](docs/operations.md) · [密钥保管](docs/local-key-generator-privacy.md) · [Stash 3.4.1](docs/stash-3.4.md)

请勿公开客户端配置、订阅链接、密钥或备份。文档中的域名、公网地址和截图均为示例。
