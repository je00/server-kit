# Desktop SSH updates / 桌面端 SSH 更新

## Upgrade / 升级

Updating the VPS updates downloadable scripts, not copies already on your devices.
Download the new Windows/macOS script from the dashboard and run **enable** once
with your existing SSH port, as administrator/root. Keep an independent connection
open until both the LAN and AWG entry points have been checked.

更新 VPS 只更新面板提供的下载文件，不会替换设备上的旧脚本。重新下载 Windows/macOS
脚本，以管理员/root 运行一次“开启或修改 SSH 端口”，使用原端口。保留独立连接，确认
局域网和 AWG 入口均可用后再关闭。

## Behavior / 行为

- Installed OpenSSH is reused; unchanged SSH configuration is not restarted.
- Windows uses a startup task and a one-minute recovery check, plus service failure retries.
- macOS uses launchd and a 30-second recovery check.
- Recovery only binds addresses in the configured allowed networks. No wildcard listener is added.
- Recovery pauses during a pending SSH authentication transaction. Explicitly disabling SSH also disables recovery.

- 已安装 OpenSSH 时跳过组件查询；配置及监听无变化时不重启。
- Windows 开机检查并每分钟对账，服务异常退出另有失败重试。
- macOS 使用 launchd，每 30 秒检查一次。
- 仅绑定允许网段对应的本机地址，不新增全接口监听。
- SSH 认证等待确认期间暂停网络对账；主动关闭 SSH 时同时停用恢复任务。

Recovery is eventual, not zero-downtime. The tunnel must actually become available;
network changes may require one SSH restart. This does not install, reconnect, or restart AWG itself.

恢复不是零中断：隧道必须先可用，地址变化可能需要重启一次 SSH。恢复任务不会安装、
重连或重启 AWG 本身。
