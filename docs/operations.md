# 运维指南

[返回快速部署](../README.md)

高级操作参考；首次安装请先完成 README。下文默认从仓库目录运行源码命令。

本仓库包含 AmneziaWG、文件订阅、VLESS、Git、Mosh、安全和防火墙管理脚本。

## 安装全局命令

在服务器仓库目录运行：

```bash
bash install-server-kit.sh install
```

全新服务器的管理平面使用引导式初始化：

```bash
server-kit preflight
server-kit init
```

初始化建立 AWG 管理入口和内网管理网站，不修改 SSH 或应用 server-kit 的主机入口防火墙策略；AWG 安装会启用转发及自身所需的网络规则。
详细安全模型和分阶段范围见 [管理平面设计](management-plane-design.md)。

更新已经初始化的管理网站：

```bash
bash ./server-kit update-web
```

更新使用新版本目录和原子软连接切换，同时验证 HTTP 健康状态与 Unix Socket 管理 seam；
失败会恢复旧版本。更新不会修改管理员密码、AWG、SSH 或防火墙。

当前网页可查看全部十类托管服务的运行事实，并提供可中断继续的首次部署向导。向导可安装
VLESS、Clash 订阅、Mosh 和普通文件服务；SSH 与防火墙始终使用自动回滚事务。
节点页统一管理 AWG 普通节点、VLESS 单向节点及其目标/协议/端口权限。AWG 普通节点默认允许
访问全部内网节点和端口；目标与端口可以独立选择“全部”或具体值。撤销默认授权后，才仅应用
其余逐项授权。VLESS 节点使用同一套模型，但新建时默认没有任何内网授权。新的 AWG 节点由
管理网站在当前浏览器生成私钥、主/备双入口配置与二维码，VPS 只接收公钥和预共享密钥，也不提供完整配置领取入口。新增 AWG 或 VLESS 节点会在同一任务中自动发布订阅；节点卡片可直接复制链接、显示二维码、停用、恢复和轮换令牌，
停用发布不会禁用节点。机场资源支持多个机场、按机场和国家/地区启用，以及最多 16 个命名出口节点，并可做脱敏可达性检查。出口目录始终有一个默认出口；AWG 与 VLESS 节点未单独保存选择时跟随默认，也可勾选多个出口发布到自己的订阅。发布的 EXIT 和 VLESS 中转节点会使用出口资源的英文名称，不暴露内部资源 ID；每个出口拥有独立的 `SERVER.RELAY.VLESS.<出口名>` 双端口组，并逐组加入 PROXY。删除默认出口前必须有替代出口，系统会自动提升剩余出口并清理节点引用。

敏感配置和完整订阅链接只向超级管理员开放，而且领取前必须用当前密码重新认证，解锁时间为 5 分钟。
管理员可以管理服务、节点、权限、机场资源和发布状态，但不能读取密钥或完整链接；只读账号只能查看
脱敏事实和审计。账号维护、敏感资源领取和所有 root 变更都进入同一条哈希审计链。
SSH 认证与防火墙安全事务页提供候选差异、验证清单、自动回滚倒计时与确认流程
持久化和立即回滚使用同一个受限管理接口。正式服务器默认只开放预览；只有一次性测试机
完成断线与自动回滚验证后，才允许通过 systemd 临时配置开启高风险写操作。
“配置备份”页面可用独立恢复口令创建 AES-256-GCM 加密备份、下载密文、校验完整性并只读预览恢复范围。
备份包含 AWG、VLESS、SSH、订阅、访问策略和管理网站一致性快照，不包含 Git 仓库；恢复口令不保存，
也不会进入命令行、环境变量或管理审计。覆盖恢复会先保存 root 专属短期回滚包，写入磁盘后进入 5 分钟确认窗口；
期间不主动重启 AWG、SSH 或 VLESS，未确认自动恢复原文件。`server-kit recovery` 也可以从 SSH 或云控制台立即回滚。
为避免正在操作的网页会话出现“操作已执行但响应失败”，管理网站 SQLite 数据库和网站签名密钥不参与在线覆盖，
只保存在加密备份中并标记为需要控制台离线恢复。
未完成事务验收的服务器只开放恢复预览；完成一次性测试机验证后，可通过 systemd 配置启用实际覆盖恢复。
AWG/VLESS 节点与订阅写操作使用独立开关和全局变更锁；初始化管理节点不能从网页禁用或删除。所有写操作记录到
`/var/log/server-kit/management-actions.jsonl`，日志不包含密钥、UUID、密码、机场链接或访问令牌。

脚本会把所有管理脚本软连接到 `/usr/local/bin`。之后可在任意目录直接运行，例如：

```bash
server-kit-manager.sh
amneziawg-setup.sh list
```

统一查看服务、节点数、订阅数、监听端口和当前防火墙策略：

```bash
server-kit-manager.sh status
server-kit-manager.sh audit
server-kit-manager.sh logs vless
server-kit-manager.sh restart clash
```

查看和管理开机自启：

```bash
server-kit-manager.sh autostart
server-kit-manager.sh enable-autostart vless
server-kit-manager.sh disable-autostart clash --yes
```

自启命令只影响下次开机，不会立即启停当前服务。Git 和 Mosh 依附系统 SSH 按需启动，
没有独立常驻服务；SSH 和防火墙是保护项，总管只显示状态，不允许禁用。禁用 AWG
可能造成重启后失去内网入口，因此还必须显式添加 `--force`。

总管会根据终端宽度自动排版：宽度达到 96 列时，状态、自启、端口和帮助使用
Tab 数据配合 `column` 对齐；如果服务器缺少该命令，总管会自动安装 `bsdextrautils`。
手机等窄终端使用分组短列表。需要预览时可以临时设置
`COLUMNS=140` 或 `COLUMNS=40`，不会改变服务配置。

`server-kit-manager.sh stop all --yes` 会停止除 SSH 外的套件服务，并把 AWG
隧道放在最后。当前 SSH 依赖待操作隧道时会拒绝执行，只有确认存在其他入口后才能加
`--force`。系统 SSH 始终是只读保护项，监听变更仍由 `debian_security_manager.sh` 完成。

## SSH 与防火墙加固

先把 SSH 改为仅密钥登录；应用后会启动自动回滚，必须从独立终端验证公网和 AWG 两条新连接：

```bash
debian_security_manager.sh ssh-auth-plan
debian_security_manager.sh harden-ssh-auth
debian_security_manager.sh confirm-ssh-auth --yes
```

防火墙会读取 `/etc/server-kit/ports.json` 生成候选规则，但扫描结果不会自动应用：

```bash
debian_firewall_manager.sh plan
debian_firewall_manager.sh check
debian_firewall_manager.sh apply --yes
debian_firewall_manager.sh confirm --yes
```

当前使用 nftables 的独立 `inet server_kit_filter` 规则表。查看内核中实际加载的
原始规则：`nft list table inet server_kit_filter`。

`server-kit-manager.sh audit` 还会核对 systemd 防火墙状态与内核规则表，避免服务显示
运行但规则已被外部命令清空。若公网 IPv4 发生变化，HTTPS 发布服务会在开机后两分钟及
每日证书检查时运行 `debian_file_manager.sh reconcile-public-ip --yes`：保留现有下载令牌
和端口，对账稳定发布入口证书，并同步 Clash 订阅与普通文件地址。也可手工执行该命令立即
对账；`debian_file_manager.sh audit-public-ip` 只检查、不修改。

`apply` 会先安排自动回滚；只有独立验证公网 SSH、AWG SSH、VLESS、Clash 订阅和 AWG UDP 入口后才能确认。防火墙使用独立的 `server-kit-firewall.service`，不会启用或加载含 `flush ruleset` 的系统 `/etc/nftables.conf`。Certbot 续期只在事务期间临时开放 TCP 80。

## AmneziaWG 与受限 VLESS

普通节点使用系统级 `awg0` 获得双向内网能力，默认完全互通，也可按来源节点收紧为目标、协议和端口允许列表；手机等 VLESS 节点使用独立 UUID，只能访问服务端策略明确放行的目标和端口。普通节点策略保存在 `/etc/server-kit/awg-access.json`。

```bash
amneziawg-setup.sh install
printf '<客户端生成的预共享密钥>\n' | amneziawg-setup.sh import-public home-desk '<客户端公钥>' 10.20.0.101
amneziawg-setup.sh endpoints

debian_vless_manager.sh client-add home-iphone
debian_vless_manager.sh allow home-iphone vps 22
debian_vless_manager.sh plan
```

AWG 默认提供 `443/UDP` 主入口和一个首次安装时固定生成的随机低位备用入口。

为降低 VPS 公网 IPv4 变化的恢复影响，可在管理网站“域名管理 → 稳定公网入口”通过回滚级任务配置专用 FQDN。应用后进入 5 分钟回滚窗口，必须从另一条独立登录连接确认；应用会联动迁移 AWG/VLESS 节点入口、HTTPS 证书、Clash/普通文件发布地址和订阅内容，超时、手动回滚或任一步失败都会恢复旧入口、旧证书和旧链接。未配置时继续使用当前 IP。新安装的 VLESS、SSH 高位公网入口和 server-kit 防火墙不再绑定单个易变公网 IPv4；既有节点需按 runbook 完成一次性迁移。

管理网站通过服务商选择器支持腾讯云 DNSPod 和 DuckDNS，两者都是同级可选的动态 DNS 服务商；只有明确选中后才显示相应配置字段，后续服务商可沿同一结构扩展。DNSPod 模式填写目标完整域名、主域名、SecretId 与 SecretKey：若目标名称不存在，server-kit 会使用当前默认路由公网 IPv4 自动创建唯一的默认线路 `A` 记录；若存在唯一的默认线路 `A` 记录则更新；同名多记录、CNAME 或非默认线路会被拒绝，不会选择或覆盖其他记录。真实更新成功后才原子保存凭据；定时器启用或系统开机后约 1 秒开始上报，网络尚未就绪或服务商暂时失败时每 5 秒重试，成功后继续每分钟对账。DuckDNS v1 配置继续兼容。凭据只保存在 VPS 的 root-only `/etc/server-kit/duckdns.json`，任务数据库仅保存加密候选载荷，网页、状态接口和审计日志均不回显。腾讯云 API 子账号应仅授予目标 DNSPod 域名的查询、创建及动态更新权限。

“全局订阅强制解析”集中维护 FQDN 到 AWG 内网节点地址的映射，并把同一份记录写入所有 Clash/Stash 发布订阅；VLESS 订阅还会同步 `proxy-hosts`，Xray 服务端同步对应 DNS hosts。允许使用开头的 `*.` 通配符，但若通配符会覆盖 VPS 的稳定公网入口或当前动态 DNS 域名，预览和实际写入都会拒绝。

Clash/普通文件的 HTTPS 下载站点共用稳定入口证书，但保留各自端口和访问令牌。不同主机名仍可在不同设备独立签发证书；已导入客户端的节点可随 DNS 恢复，但 DNS 缓存意味着该方案不能承诺零中断。完整事前准备、旧配置本地迁移和灾后步骤见 [公网 IP 变更 runbook](public-ip-change-runbook.md)。

## Mosh 内网终端

Mosh 使用 `10.20.0.1:60001-60010/UDP`，防火墙同时限制 `awg0` 接口和
`10.20.0.0/24` 来源，公网不会开放这些端口。Mosh 按需启动，没有常驻服务；每个活动窗口占用范围内一个端口，断开后可重新连接原会话。

```bash
debian_mosh_manager.sh install
debian_mosh_manager.sh status
debian_mosh_manager.sh stop
debian_mosh_manager.sh uninstall --yes
```

客户端也需要安装 Mosh，并先连入 AWG：

```bash
mosh -p 60001:60010 --bind-server=10.20.0.1 root@10.20.0.1 -- tmux new -As main
```

`stop` 和 `uninstall` 都会终止活动会话并从防火墙撤销 UDP 60001-60010。Windows 没有原生客户端时可通过 WSL 使用；SSH、Git、SCP 和端口转发仍使用原来的 SSH。

查看或卸载软连接：

```bash
install-server-kit.sh status
install-server-kit.sh uninstall
```

卸载只删除软连接，不删除仓库和服务配置。

## Clash 个性化订阅

`install-clash` 默认读取同目录的 `clash_skeleton.yaml`，并引导填写首个机场订阅和完整 Mihomo 出口节点。当前 VLESS 中转会从 Xray 配置自动读取：

```bash
bash debian_file_manager.sh install-clash
```

机场目录和出口参数保存在 `/etc/server-kit/clash-inputs.json`，权限为 `600`，不进入 Git。安装完成后在管理网站“机场资源”页添加、修改、停用或删除机场，并勾选需要加入 `PROXY` 的国家/地区。旧版单机场事实会在首次写操作时自动迁移；修改自定义规则仍编辑 `clash_skeleton.yaml` 后刷新订阅。

每个 AWG/VLESS 节点可在“内网节点 → 配置”独立启用订阅纯净模式。普通订阅把 `MID` 分组排在所有机场分组之前；纯净订阅会完整移除机场 Provider 和机场分组，并从 `PROXY` 隐藏 `MID` 及其链式出口，但保留 `MID` 分组用于查看 443/2053 延迟。该开关只刷新订阅，不重启 AWG 或 Xray，也不改变节点权限；默认关闭以兼容已有节点。

客户端支持 VLESS REALITY、但不支持 `dialer-proxy` 时，可在现有 443/2053 入站启用服务端 VLESS 转发。每个“订阅 × 出口”组合都会获得独立 UUID，并生成 ASCII 节点名 `SERVER.RELAY.VLESS.<EXIT_ID>.443` 与 `.2053`，由唯一的 `SERVER.RELAY.VLESS` fallback 组直接引用；VLESS 客户端订阅发布全部出口，AWG 订阅只发布该节点选中的出口。`PROXY` 把该组放在成员第一项作为默认首选，不再生成额外的 DNS 中转组。VPS 按身份把流量固定路由到对应 SOCKS5 出口，私网目标会在 VPS 上拒绝。普通境外 DNS 跟随当前 `PROXY`，国内和直连 DNS 使用国内 IP DoH；节点启动解析及机场分组的客户端兼容策略见 [Stash 3.4.1 说明](stash-3.4.md)，不要将业务 DNS 与节点入口解析混为一谈。现代 Stash VLESS 订阅的空机场组使用 `REJECT`，不会静默回退直连；AWG 与旧兼容投影按各自策略生成。所有订阅均把 `PROXY` 放在策略组第一项，降低误选内部组的概率。该模式不增加公网端口：

```bash
debian_vless_manager.sh relay-vless-enable
```

若曾启用旧版 Shadowsocks 救援入口，可用 `debian_vless_manager.sh relay-shadowsocks-disable` 同时删除 Xray 入站、订阅节点及其 TCP/UDP 防火墙规则。

## 出口一致 DNS

出口一致 DNS 可按出口启用，适用于代理供应商的域名解析位置与业务出口不一致的情况。需要支持出站 `targetStrategy: ForceIPv4` 的 Xray（已验证 26.3.27）和已启用的 VLESS 服务端转发：

```bash
# 将 EXIT_ID 替换为 clash-inputs.json 中的出口 ID；可列出多个 ID。
debian_vless_manager.sh relay-dns EXIT_ID
debian_file_manager.sh refresh-clash
# 不带出口 ID 关闭该模式；随后同样刷新订阅。
debian_vless_manager.sh relay-dns
```

模式配置保存在 root-only `/etc/server-kit/server-relay.json` 的 `dns_consistent_exit_ids`。每个选中的出口运行一个独立 Xray 实例，拥有独立 DNS 缓存和固定的上游出口。客户端流量经主 Xray 转交到带独立认证、仅监听 `127.0.0.1` 的 SOCKS 入站；业务域名先经该出口查询 `https://1.0.0.1/dns-query` / `https://8.8.8.8/dns-query`，成功后只把 IPv4 交给供应商。DNS 分支只允许这两个 IP 的 TCP 443，使用不做目标解析的原始 SOCKS 出站；供应商网关域名仍由系统 DNS 独立启动解析。没有指向主 Xray、worker 自身或本机 DNS 的回路，DoH 失败时请求失败，不回退到供应商域名解析或 VPS 直连。私网 IP 和解析到私网的目标在 worker 内拒绝。

`relay-dns` 先校验并启动 worker，经带域名的真实 TLS/HTTP 请求验证后才切换主 Xray；失败时恢复 worker 和主配置。worker 使用 `server-kit-exit-dns@<ID>.service`，配置在 `/etc/server-kit/exit-dns/`，随开机启动并自动重启。部署不修改 AWG、SSH、防火墙或默认路由；主 Xray 切换可能短暂重建公网代理连接。未启用该模式的出口保持原行为。

刷新订阅后，启用模式的 `EXIT.*` 节点也改用同身份的 VLESS 服务端入口；旧 Stash 继续使用其服务端中转组。已导入的客户端需要更新订阅，旧的直接 SOCKS 节点不会自动获得此保护。该模式保证解析请求经过同一出口，不能保证第三方 GeoIP 数据库永远标注同一城市，也不改变供应商限制的目标网站。
