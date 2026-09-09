# 票据 002：Clash 机场投影

状态：已完成

## 目标

把机场目录的有效选择集中投影为 Mihomo proxy-provider、国家/地区策略组和 `PROXY` 成员。

## 验收

- 仅启用机场参与投影。
- 仅被选中的国家/地区进入 `PROXY`。
- 多机场节点名称不会冲突。
- AWG 与 VLESS 发布订阅使用同一份投影结果。
- 未选择任何机场时仍生成语法有效的配置。

## 完成证据

- `lib/clash_airport_projection.py` 是机场目录到 Mihomo 配置的唯一投影 module。
- `tests/test_clash_airport_projection.py` 与 `tests/test_debian_file_manager.sh` 覆盖启停、国家筛选、空选择和真实骨架渲染。
- `tests/test_clash_bundle.py` 验证 AWG/VLESS 发布订阅保留相同机场组。
