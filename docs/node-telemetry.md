# 节点实时状态 / Live node telemetry

在 **内网节点 → 列表 / 节点连接** 查看。无需配置。

| 显示 | 含义 |
|---|---|
| ↑ / ↓ | 节点发往 VPS / 从 VPS 接收，包含内外网流量 |
| B/s | 每秒字节；K、M、G 按 1024 进位，不是 bit/s |
| 有流量 | 两次采样间计数增加，包含隧道控制流量 |
| 近期握手 | 最近 180 秒有 AWG 握手，不保证此刻连通 |
| 采样中 / 重新采样 | 尚无有效速率；不以 0 代替缺失数据 |
| 数据已过期 | 超过 8 秒没有新样本，隐藏旧速率 |
| VLESS 未开启统计 | 当前不采集，显示 —；不会自动重启 Xray |

- 可见页面每 2 秒刷新；后台页面暂停，失败时逐步退避。
- 数据新旧按 VPS 提供的样本年龄和浏览器经过时间判断，不受手机或电脑时钟偏差影响。
- AWG 由管理代理共享采样，只读计数，不执行连通性探测。
- 节点图的权限配置每 30 秒刷新；切换已查看节点复用短期缓存，手动刷新立即重读。
- 首次采样、计数回退、接口或节点身份变化、超过 10 秒断档，先重建基线。
- VPS 中心不显示不完整的合计；权限线与节点状态独立，状态不改变授权。

## English

Open **内网节点** (Nodes), in list or graph view. No setup is needed.

- **↑ upload / ↓ download:** total node ↔ VPS traffic, including tunnel control traffic; bytes/s, not bits/s.
- Visible pages refresh every **2 seconds**. Hidden pages pause. Samples older than **8 seconds** show no rate.
- Freshness uses server-reported sample age and elapsed time, not your device's clock.
- AWG uses shared, read-only counter samples. A recent handshake is not a live connectivity check.
- Missing or reset samples show **—**, not a false zero. VLESS statistics remain off; Xray is not restarted.
- Graph permissions refresh every **30 seconds**. Manual refresh bypasses the browser cache. Status never changes access rules.
