# Stash 3.4.1: node DNS / 节点启动解析

## Behavior / 行为

- Only **exact proxy `server` hostnames** receive direct encrypted DNS (DoH).
  No wildcard, subscription URL, SNI or benchmark hostname is imported.
- Existing domestic direct-DNS policies, website DNS, routing and LAN mappings
  stay unchanged. Website DNS that used the selected exit still uses that exit.
- Remote airport providers remain on the client. The VPS does not fetch the
  airport subscription; a VPS-side HTTP 403 does not block this import workflow.
- Airport groups contain a permanent `REJECT` member. Their filters include it
  and exclude the provider's `DIRECT` placeholder, including the all-regions group.
  This does not add another exit or a dependency back to `PROXY`.
- Native provider benchmark fields keep new nodes on the same Stash test target.

仅节点的完整入口域名直连 DoH；保留原有国内直连 DNS、网站分流和内网配置。
机场订阅仍由客户端更新，不需要 VPS 拉取，不增加节点。机场组为空时拒绝连接，
不回退直连或其他出口。此投影用于现代 VLESS 订阅，AWG 和旧版兼容订阅不变。

## Import entry domains / 导入节点域名

Stash 3.4.1 cannot rely on the newer `proxy-server-nameserver` feature. Import
an exact-domain inventory from a trusted, current client provider cache first.
The inventory contains **hostnames and a subscription URL fingerprint only**:
no subscription URL, password, UUID or full proxy configuration.

在客户端缓存所在机器运行（替换示例路径与机场 ID）：

```sh
python3 lib/stash_bootstrap.py export \
  --airport-id 111111111111 \
  --client-config /private/client.yaml \
  --provider-cache /private/airport-cache.yaml \
| ssh root@SERVER python3 /opt/server-kit/current/lib/stash_bootstrap.py import \
    --airport-id 111111111111 --config /etc/server-kit/clash-inputs.json
```

Install the updated code on both sides first. The importer checks that the URL
fingerprint matches the configured airport and stores the inventory with mode
`0600`. It prints only success and the domain count. A changed subscription URL
invalidates the old inventory; ordinary name/country edits preserve it.

先安装新版代码。导入命令只更新域名清单，不刷新订阅或重启任何服务；之后需生成并
发布新主订阅，再在 Stash 更新主配置。不要把清单、缓存或生成后的私人订阅提交到 Git。

## Limits and checks / 限制与验收

- No inventory means no airport-domain exceptions. New entry **IP addresses**
  work through DNS automatically; new entry **hostnames** need a new import and
  main-profile refresh. Never expand to a wildcard or all-domain direct resolver.
- Direct DoH hides queries from passive network observers, not from the chosen
  DNS provider, which can see the client IP and node hostname. This is an explicit
  bootstrap exception, not a claim of zero information disclosure.
- The logged iCloud `resource deadlock avoided` error is a separate client-cache
  issue. This patch does not repair iCloud. An unavailable airport should reject
  traffic rather than silently use DIRECT.
- Configuration tests do not replace Stash 3.4.1 device testing: keep an airport
  selected, refresh the main profile and provider, then benchmark without switching
  exits. Check LAN access, the original domestic rules, DNS exit behavior, empty
  groups and a cold start. Do not change AWG, SSH or firewall services for this test.

没有清单或新增入口域名未导入时，仍可能无法解析该节点；不会因此开放所有 DNS 直连。
真机需验证刷新后不切出口测速，以及国内直连、内网、DNS 出口和空机场组行为。

References: [Stash DNS](https://stash.wiki/features/dns-server),
[groups](https://stash.wiki/proxy-protocols/proxy-groups),
[providers](https://stash.wiki/proxy-protocols/proxy-providers).
