# 阶段 04 · DeepSeek 实施交接

本文件供接手代码开发的 agent 使用。阶段 01–03 已完成；当前阶段的研究规则见方法设计，通用能力按基础设施计划单独建设。不要从旧阶段概述或废弃的 `pilot实施安排.plan.md` 重启规划。

当前状态：**任务 07 并发实施已完成并复核通过（E30/E31）**。任务 06、E28 串行配置和全部历史证据保留，不重复实现。**方法目录已包化并新增只读消息导出，见 [E32](./验收记录.md#e32)/[E33](./验收记录.md#e33)/[E34](./验收记录.md#e34)**：`method/` → `method/single_candidate_ab/`（顶层兼容转发、公开名单与导入路径不变），方法文档迁至 `method/single_candidate_ab/`（含 `plans/`），旧路径保留导航 stub；新 CLI `export-mutator-messages`（HTML/JSONL/manifest，按 `(action_id, request_attempt_id)` 关联，复用 `ActionStore` 读 API）。接口零破坏，全量 564 passed，文档链接 0 missing；首导目录已交付于 `cocota_runs/phase04/methods/single_candidate_ab/exports/method-ab-flash-v32-concurrent-r1/run1-first-export-20260928/`。`method/README.md` 汇总方法索引、公共导出入口与目录约定；`implicit_then_literal/README.md` 仅为设计草案/未裁定。未改变 A/B 行为、配置身份、缓存键或研究门，未发起新实验。

并发交付位于 `cocota_runs/phase04/method-ab-flash-v32-concurrent-preflight-20260923/`：示例检查 3、victim 请求 4、mutator/A/B 决策串行。下一步是[实际环境检查与启动](method/single_candidate_ab/实验启动说明.md)，本轮尚未执行，勿把已有只读预检当成真实 Docker/API 验证。

## 1. 最小阅读顺序

| 顺序 | 文档 | 阅读目的 |
| --- | --- | --- |
| 1 | [主方案](../CoCo-Attack%20DSPy%20重建实施方案.md#shared-contracts) | 阅读入口、实施范围/探索期补充、运行控制、B–I 公共契约及文档规范。公共指标、执行隔离和缓存规则以这里为准 |
| 2 | [迭代方法设计](method/single_candidate_ab/迭代方法设计.md) | 理解要落地的研究流程，重点 §3/§5/§6/§7/§8：单候选、A 示例硬门、一次性 B、模型输入和历史 |
| 3 | [阶段裁定记录](./验收记录.md) | 重点 D02–D04；避免沿用“A 失败仍进入 B”、固定十次调用、通用层内置 A/B 等已撤回解释 |
| 4 | [基础设施独立计划](./infrastructure/迭代基础设施实施安排.plan.md) | 确认 I1–I6 职责、已有代码入口及不重建阶段 01–03 的边界 |
| 5 | [方法实施安排](method/single_candidate_ab/迭代方法实施安排.plan.md) | 了解基础设施如何接入当前方法，保留 DeepSeek 已补的四项接线注意事项 |
| 6 | [当前 sub-plan：07 示例检查与模型采样并发](method/single_candidate_ab/plans/07-示例检查与模型采样并发.plan.md) | 先读 E30/E31；并发实现已复核，按启动说明准备后续运行，不重复开发 |

不要求重新通读阶段 01–03 全部计划、日志或历史研究资料。遇到某条历史裁定/输入来源问题，再按链接查对应记录。[知识蒸馏](../../coco_attack_知识蒸馏.md)与[功能需求](../../coco_attack_functional_requirements.md)的职责拆分已在基础设施计划 §2 汇总；它们是来源材料，不覆盖后续用户决定。

## 2. 必须保持的边界

- 通用服务提供事实，具体方法决定阶段、硬门、修改内容和停止；公共服务不导入方法模块。
- 当前方法只有一个当前候选。A 改写示例代码通过功能、oracle 命中、Semgrep 不命中三项门后才能进入 B；未通过留在 A。B 每个大迭代只有一次 cot 修改机会，可同时修改三个示例。
- A 门检查投毒示例，不等于 victim 实际逃逸；训练 ASR/evasion 单独计算并作为反馈。A/B 不加入 `search/holdout` 阶段枚举。
- 复用现有静态 oracle、Docker harness、分类器、指标与缓存语义，不修改判定器来制造过门；历史或参考判定的新差异先整体报告。
- 原始资产、阶段 01–03 结果只读；产物写显式指定的新目录。同版本恢复，不建迁移层。缓存恢复不增加独立证据或重复成本，未知消耗不填零。
- 仅功能测试结果缓存已获本期实现范围；不扩展总预算、全层缓存、强制数据权限、候选池或通用工作流框架。
- 不覆盖其他协作者的未提交修改；尤其保留方法计划的语义边界、静态入口、clean 集成陷阱、模型输入素材四项修订。

方法、文件名和类名尚可调整。常规工程选择直接按现有代码作最小实现；只有需要改变研究行为、公共判定口径或遇到无法归因的历史差异时，才列出具体问题。

## 3. 开发顺序与计划粒度

| 次序 | 工作 | 依据及计划安排 |
| --- | --- | --- |
| 1 | 示例代码检查服务：功能、oracle、Semgrep | 已实现，证据见 E04；比较版本收尾见 E05，不阻塞 I1 |
| 2 | 模板快照、稀疏补丁与投毒物化 | 已实现，证据见 E06，交接核对见 E07 |
| 3 | 单候选训练生成、评估与基线反馈 | 已实现 mock 链路，修复见 E10/E12/E14，交接复核见 E13 |
| 4 | 多轮 mutator、动作恢复、反馈历史 | 已交付，证据 E16；§0 三处接线收尾已在 E18 完成 |
| 5 | 一轮 A→B，再扩到 5 个大迭代 | [05 sub-plan](method/single_candidate_ab/plans/05-单候选AB方法接入.plan.md) 主体与 F1–F4 已有实施证据（E18/E20），专项复核见 E21 |
| 6 | 角色来源接线与运行预检 | [06 sub-plan](method/single_candidate_ab/plans/06-角色来源接线与运行预检.plan.md) 已复核（E26/E27）；配置与只读预检已完成（E28） |
| 7 | 示例检查与 victim 请求并发 | [07 sub-plan](method/single_candidate_ab/plans/07-示例检查与模型采样并发.plan.md) 已交付并复核，见 E30/E31 |

第 1–6 项已有实现与检查证据，配置与只读预检也已完成（E28），第 7 项亦已交付并复核，后续实际运行范围另定。后续按实际接口补短计划，每份写清接口、复用点、必要检查和交付即可；不要预先复制主方案、建立额外验收体系或为每个模块写计划。

当前任务复用已验证的角色配置、来源和预检入口，整理本次实际输入与可审阅配置。真实运行配置未齐时报告具体缺项；不自行选择科研模型，不发起真实请求。

## 4. 每次代码交付

交付源码、少量必要检查和可复现入口；报告实际执行的命令、结果、产物路径以及未执行/受环境阻塞项。真实容器证据与 mock 分开，自动检查通过不代签人工验收。

执行证据追加到[阶段过程记录](./验收记录.md)，用下一个未占用 E 编号；同步[阶段概述当前状态](./阶段概述.md#current-status)。plan 只维护工作安排，不另建每项独立验收文档。没有用户要求时，不自动提交 Git、推送或开启真实模型实验。

## 5. 后续运行交接

任务 07 已完成，不再发送旧的并发开发提示。接手运行前先读 E30/E31，并使用[启动说明](method/single_candidate_ab/实验启动说明.md)当前并发版命令：

1. 对 `cocota_runs/phase04/method-ab-flash-v32-concurrent-preflight-20260923/execution_config.json` 做实际 `check-execution`，输出到新的 startup 目录。检查会访问 Docker；不能用 preflight-method 报告替代。
2. 环境检查通过后，使用同目录 `method_config.json` 启动 `run-method-ab --allow-real-checks --allow-real-training`。这是实际模型与工具运行，不是离线验证。
3. 预定 `cocota_runs/phase04/method-ab-flash-v32-concurrent-r1/` 已含一次真实批次产物（14 逻辑动作/20 尝试）；本轮仅将其作为只读导出输入，未恢复、未重评估、未作研究结论。任何新运行使用新目录，不续写或覆盖既有 run。
4. 只读审阅 mutator 消息：`python -m coco_attack export-mutator-messages --run-dir <run 目录> --output-dir <全新目录>`，输出 `index.html`/`messages.jsonl`/`manifest.json`；纯读取，不调用恢复/模型/密钥/Docker/Semgrep。方法目录已包化并新增只读消息导出（E32/E33）；`-concurrent-r1` 的首导目录为 `cocota_runs/phase04/methods/single_candidate_ab/exports/method-ab-flash-v32-concurrent-r1/run1-first-export-20260928/`；新产物按 `cocota_runs/phase04/methods/<method_id>/exports/...` 约定放置。

本轮未执行上述模型/工具步骤。后续收到实际运行任务时按明确范围执行并追加 E 记录；不重建阶段 01–03，不运行 25 题，不改 oracle/指标/划分。配置中的五轮是批次上限，A 未过门的尝试数不固定。
