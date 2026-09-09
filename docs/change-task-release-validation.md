# 变更任务引擎发布验收

验收日期：2026-08-08

## 自动测试

- 核心控制面：150 项测试通过。
- Django 管理网站：57 项测试通过。
- 全部 Shell 管理脚本测试通过；真实 nftables 隔离项由下述隔离机回归覆盖。

## 隔离机回归

在正式机上使用独立网络命名空间和可丢弃的 overlay 根文件系统启动 Debian 13 nspawn 隔离机，未直接修改正式机配置。

- 网页停止或客户端断开后，已提交任务继续执行并成功落盘。
- 管理代理在任务运行中被强制终止后，任务进入 `interrupted`，不会盲目重放。
- 冷启动后 31 条历史任务及其 26 条成功、4 条失败、1 条中断状态完整保留。
- SSH 认证、SSH 监听和防火墙事务均拒绝原会话确认；独立连接可确认，超时可自动回滚。
- AWG 内网 SSH 始终保留；测试公网 SSH 新端口仅在独立确认后保留。
- 配置恢复验证了正确口令、错误口令、独立确认、代理崩溃和自动回滚；回滚恢复的是事务开始前状态。

## 正式机发布

- 首次任务引擎实现提交：`1411bb0befe25c7c6100e460f60872ca52c5ea92`。
- 原版本：`/opt/server-kit/releases/bootstrap-20260808101843-166315`。
- 首次任务引擎迁移识别旧代理后，通过原子软连接切换到 `/opt/server-kit/releases/bootstrap-20260808150120-186303`。
- HTTP 健康检查返回 `{"status":"ok"}`，Unix Socket 任务查询返回“没有活动变更任务”。
- 发布前后 SSH 监听配置和 nftables 规则文件 SHA-256 完全一致。
- 公网 SSH、AWG SSH、AWG 握手、管理网站、Xray、Clash 订阅、防火墙和证书续期均正常。
- 普通文件服务没有已发布资源，维持已启用但未运行的既有状态。
- 隔离回滚验收通过后，正式机启用 `SERVER_KIT_HIGH_RISK_WRITES=1`，代理和网站健康检查再次通过。

发布清理阶段发现旧更新流程会把 `/usr/local/bin` 软链指向临时源码目录。第一次修复发布因 Unix Socket 健康检查无法调用该失效命令而自动回退，证明发布回滚路径有效。最终实现提交 `7923da7dd9dd03ad7c6aa605f129d90b507dd6e6` 将全部 CLI、依赖库和模板纳入不可变 release，并在代理功能检查前原子切换命令；任何命令检查失败都会同时恢复旧 release 和旧软链。

最终正式 release 为 `/opt/server-kit/releases/bootstrap-20260808151515-189137`。10 个全局命令均解析到该目录；`server-kit-manager.sh snapshot`、`server-kit-manager.sh audit`、公网 SSH、AWG SSH、HTTP 健康检查、Unix Socket、AWG 握手和 nftables 复核全部通过。端口审计结果为零监听漂移、零未托管公网端口。

`networking.service` 因历史 `/etc/network/interfaces` 仍引用不存在的 `eth1`，自 2026-08-06 起处于失败状态；该状态早于本次发布，未影响当前公网接口、AWG 或受管服务，也未在本次变更中擅自修改。
