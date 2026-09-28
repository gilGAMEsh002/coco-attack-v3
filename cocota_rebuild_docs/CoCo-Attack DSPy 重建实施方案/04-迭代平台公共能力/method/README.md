# 阶段 04 · 方法目录（method）

本目录按方法拆分研究规则与文档。通用执行能力仍在 `coco_attack/src/coco_attack/iteration/`，
不随本目录调整。本目录同时是阶段 04 方法文档与运行产物的导航入口。

## 目录结构

```text
method/
├── README.md                     # 本文件
├── single_candidate_ab/          # 当前已实现的方法
│   ├── 迭代方法设计.md
│   ├── 迭代方法实施安排.plan.md
│   ├── 实验启动说明.md
│   └── plans/
│       ├── 05-单候选AB方法接入.plan.md
│       ├── 06-角色来源接线与运行预检.plan.md
│       └── 07-示例检查与模型采样并发.plan.md
└── implicit_then_literal/        # 设计草案（未裁定、不构成需求）
    └── README.md
```

六个迁移文档的旧路径（`method/迭代方法设计.md` 等）保留为导航 stub，历史记录中的旧链接
仍可跳转；正文与后续更新只在新位置维护。阶段验收记录、E/D 编号与历史结论不迁移、不改写。

## 与代码的对应

当前方法实现位于 `coco_attack/src/coco_attack/method/`：

| 路径 | 职责 |
| --- | --- |
| `method/__init__.py` | 顶层兼容入口，公开名单 20 项保持冻结 |
| `method/preflight.py` | 兼容转发到包内预检实现 |
| `method/single_candidate_ab/__init__.py` | 方法包入口（原公开名单 + `PHASE_DONE`/`PHASE_PAUSED`；`A_FIELD`/`B_FIELD` 可直接导入） |
| `method/single_candidate_ab/runtime.py` | 方法状态机、A/B 门、单候选与共享历史 |
| `method/single_candidate_ab/preflight.py` | 离线只读预检报告 |

既有导入路径 `coco_attack.method.single_candidate_ab` 与 `coco_attack.method.preflight` 继续可用。

## 运行产物目录约定（新增）

后续方法运行与导出统一放在：

```text
cocota_runs/phase04/methods/<method_id>/
├── runs/<run_name>/              # 配置、预检、run/、snapshots/
└── exports/<run_name>/<export_id>/
```

`<method_id>` 例如 `single_candidate_ab`。此约定只用于新配置示例与启动说明；既有配置与
运行产物原位保留，不迁移、不改写。

## 消息导出（只读）

对已有 run 目录显式导出 mutator 消息：

```bash
coco_attack/.venv/bin/python -m coco_attack export-mutator-messages \
  --run-dir <run 目录，含 actions.jsonl> \
  --output-dir <全新且不与来源重叠的目录>
```

输出 `index.html` / `messages.jsonl` / `manifest.json`。该命令是纯读取：不调用恢复函数、
模型、凭证加载器、Docker 或 Semgrep，也不接入运行流程。每个逻辑动作以
`(action_id, request_attempt_id)` 关联，`history.jsonl` 仅作辅助、不用于补造模型推理。
