# 阶段 04 · 方法目录

整理作者：gpt · 2026-10-08

每种方法独立维护研究规则、实施计划和运行说明，通用能力见[基础设施入口](../infrastructure/README.md)。不要将旧方法的单候选/B 仅改 CoT 规则套用到新方法。

| 方法 | 阅读入口 | 内容 |
| --- | --- | --- |
| `implicit_then_literal` | [方法首页](./implicit_then_literal/README.md) | 当前多候选结构/字面探索；设计、接口、运行状态各自维护 |
| `single_candidate_ab` | [方法首页](./single_candidate_ab/README.md) | 旧单候选 A/B 方法及其历史实验，保留兼容接口 |

## 文件与代码对应

方法代码位于 `coco_attack/src/coco_attack/method/<方法>/`；公共服务位于 `coco_attack/src/coco_attack/iteration/`。旧顶层导入及冻结导出仍以源码为准，文档整理不改变实现。

```text
method/
├── README.md
├── implicit_then_literal/
│   ├── README.md
│   ├── 研究设计.md
│   ├── 接口参考.md
│   ├── 运行状态.md
│   ├── 实验启动说明.md
│   ├── plans/
│   └── archive/
└── single_candidate_ab/
    ├── README.md
    ├── 迭代方法设计.md
    ├── 实验启动说明.md
    └── plans/
```

## 运行产物

新产物统一放在 `cocota_runs/phase04/methods/<method_id>/runs/<run_name>/`；只读导出放在同方法 `exports/<run_name>/<export_id>/`。旧产物原位保留，不因文档迁移而修改路径或身份。

旧方法消息导出命令 `export-mutator-messages` 的输入要求见[旧方法启动说明](./single_candidate_ab/实验启动说明.md)，不能把新方法 run 当成旧格式输入。
