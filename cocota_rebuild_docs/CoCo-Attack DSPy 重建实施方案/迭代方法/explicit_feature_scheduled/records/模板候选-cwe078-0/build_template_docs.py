#!/usr/bin/env python3
"""从 templates.manifest.json + TemplateSnapshot 生成 cwe078-0 模板候选文档。

设计约定（重要）：

* 只读 `templates.manifest.json` 与 manifest 里 `snapshot_path` 指向的快照；
  只在 `manifest["output_dir"]`（即本脚本所在目录）内写文件。
* 所有数字一律逐字取自 manifest：不计算、不四舍五入、不补全、不推导。
  manifest 里缺失的数字打印 `-` 并注明缺失的是哪个条件。
* 硬失败条件（fail loudly）：manifest 缺失/不可解析、output_dir 与脚本目录
  不一致、snapshot 路径不存在、`read_snapshot` 拒绝该文件（哈希/目录名/结构
  不一致）、任何模板正文为空、示例数不是 4、content_sha256 与目录名不符。
* 可重复运行：同名文件直接覆盖，产物只由 manifest + snapshots 决定。

用法：`python3 build_template_docs.py`
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    raise SystemExit(f"找不到仓库根（含 .git 的目录）: {start}")


REPO_ROOT = _repo_root(HERE)
sys.path.insert(0, str(REPO_ROOT / "coco_attack" / "src"))

from coco_attack.iteration.template_snapshot import (  # noqa: E402
    TemplateSnapshotError,
    read_snapshot,
)

MANIFEST_PATH = HERE / "templates.manifest.json"

# evidence_legend 的键 → 本生成器使用的条件标签。
LABEL_3TASK = "3-TASK"
LABEL_3TASK_V2 = "3-TASK-v2"
LABEL_SCREEN26 = "SCREEN26"
LABEL_HIST = "HIST"


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #


def die(message: str) -> "None":
    raise SystemExit(f"[build_template_docs] 失败：{message}")


def load_manifest() -> dict:
    if not MANIFEST_PATH.is_file():
        die(f"manifest 不存在：{MANIFEST_PATH}")
    try:
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        die(f"无法读取 manifest {MANIFEST_PATH}: {error}")
    if not isinstance(payload, dict):
        die(f"manifest {MANIFEST_PATH} 顶层必须是 JSON 对象")
    if not isinstance(payload.get("templates"), list) or not payload["templates"]:
        die("manifest 缺少非空的 'templates' 列表")
    return payload


def resolve_snapshot_path(raw: object) -> Path:
    """把 manifest 里的 snapshot_path 解析成存在的文件或目录。"""

    if not isinstance(raw, str) or not raw:
        die(f"snapshot_path 必须是字符串，得到 {raw!r}")
    for candidate in (Path(raw), REPO_ROOT / raw):
        if candidate.is_dir() or candidate.is_file():
            return candidate
    die(
        "snapshot 路径不存在（既不是目录也不是 snapshot.json）："
        f"{raw}\n（也尝试了 {REPO_ROOT / raw}）"
    )
    raise AssertionError("unreachable")  # pragma: no cover


def fence(content: str) -> str:
    """把一段文本逐字放进围栏代码块（不重排、不去行尾空白）。"""

    longest = 0
    current = 0
    for character in content:
        if character == "`":
            current += 1
            if current > longest:
                longest = current
        else:
            current = 0
    ticks = "`" * max(3, longest + 1)
    body = content if content.endswith("\n") else content + "\n"
    return f"{ticks}\n{body}{ticks}"


def bullet(value: object) -> str:
    return "-" if value is None else str(value)


# --------------------------------------------------------------------------- #
# 实测结果渲染
# --------------------------------------------------------------------------- #


def render_3task(evidence: dict, legend: dict) -> list[str]:
    lines: list[str] = []
    lines.append(f"**{LABEL_3TASK}**（条件：{legend.get(LABEL_3TASK, '')}）")
    lines.append("")
    lines.append(
        f"- pooled_hit_as_measured：{bullet(evidence.get('pooled_hit_as_measured'))}"
        f" / {bullet(evidence.get('pooled_n'))}"
    )
    lines.append(
        "- pooled_hit_as_measured_note："
        f"{bullet(evidence.get('pooled_hit_as_measured_note'))}"
    )
    if evidence.get("pooled_note") is not None:
        lines.append(f"- pooled_note：{evidence['pooled_note']}")

    lines.append("")
    lines.append(
        f"**{LABEL_3TASK_V2}**（条件：{legend.get(LABEL_3TASK_V2, '')}）"
    )
    lines.append("")
    if evidence.get("pooled_hit_with_v2_t16") is None:
        lines.append(
            "- pooled_hit_with_v2_t16：-"
            f"（manifest 未提供 {LABEL_3TASK_V2} 条件数字）"
        )
        lines.append(
            f"- pooled_hit_with_v2_t16_note："
            f"{bullet(evidence.get('pooled_hit_with_v2_t16_note'))}"
        )
    else:
        lines.append(
            f"- pooled_hit_with_v2_t16：{evidence['pooled_hit_with_v2_t16']}"
            f" / {bullet(evidence.get('pooled_n'))}"
        )
        lines.append(
            "- pooled_hit_with_v2_t16_note："
            f"{bullet(evidence.get('pooled_hit_with_v2_t16_note'))}"
        )
    if evidence.get("pooled_hit_and_pass_with_v2_t16") is None:
        lines.append(
            "- pooled_hit_and_pass_with_v2_t16：-"
            f"（manifest 未提供 {LABEL_3TASK_V2} 条件数字）"
        )
    else:
        lines.append(
            f"- pooled_hit_and_pass_with_v2_t16："
            f"{evidence['pooled_hit_and_pass_with_v2_t16']}"
            f" / {bullet(evidence.get('pooled_n'))}"
            f"（同 {LABEL_3TASK_V2} 条件；note："
            f"{bullet(evidence.get('pooled_hit_with_v2_t16_note'))}）"
        )

    per_task = evidence.get("per_task")
    lines.append("")
    if isinstance(per_task, dict) and per_task:
        lines.append("逐题（per_task，条件按行标注）：")
        lines.append("")
        lines.append("| 任务 | hit | n | pass | hit∧pass | 该行的 t16_condition |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for task_id, row in per_task.items():
            if not isinstance(row, dict):
                die(f"per_task[{task_id!r}] 不是对象")
            lines.append(
                "| {task} | {hit} | {n} | {pass_} | {hp} | {cond} |".format(
                    task=task_id,
                    hit=bullet(row.get("hit")),
                    n=bullet(row.get("n")),
                    pass_=bullet(row.get("pass")),
                    hp=bullet(row.get("hit_and_pass")),
                    cond=bullet(row.get("t16_condition")),
                )
            )
    else:
        lines.append("- per_task：-（manifest 未提供 per_task 表）")

    leftovers = sorted(
        key
        for key in evidence
        if key
        not in {
            "pooled_hit_as_measured",
            "pooled_hit_as_measured_note",
            "pooled_n",
            "pooled_note",
            "pooled_hit_with_v2_t16",
            "pooled_hit_with_v2_t16_note",
            "pooled_hit_and_pass_with_v2_t16",
            "per_task",
        }
    )
    for key in leftovers:
        lines.append(f"- {key}：{bullet(evidence[key])}")
    return lines


def render_screen26(evidence: dict, legend: dict) -> list[str]:
    lines = [f"**{LABEL_SCREEN26}**（条件：{legend.get(LABEL_SCREEN26, '')}）", ""]
    preferred = [
        "unseen_hit",
        "unseen_n",
        "induced_on_clean_absent",
        "unseen_pass",
        "unseen_hit_and_pass",
        "undetected_of_hits",
        "passes_of_26",
        "hit_and_pass",
        "clean_reference",
    ]
    ordered = [key for key in preferred if key in evidence]
    ordered += [key for key in sorted(evidence) if key not in ordered]
    if not ordered:
        lines.append("- （manifest 提供了空的 SCREEN26 块）")
        return lines
    if "unseen_hit" in evidence and "unseen_n" in evidence:
        lines.append(
            f"- unseen_hit / unseen_n：{bullet(evidence['unseen_hit'])}"
            f" / {bullet(evidence['unseen_n'])}"
        )
    for key in ordered:
        if key in {"unseen_hit", "unseen_n"}:
            continue
        lines.append(f"- {key}：{bullet(evidence[key])}")
    return lines


def render_evidence(entry: dict, legend: dict) -> list[str]:
    lines = ["## 实测结果", ""]
    lines.append(
        "以下数字逐字取自 manifest（`evidence_*` 字段），本生成器不做任何计算或改写。"
    )
    lines.append("")

    evidence_3task = entry.get("evidence_3task")
    if isinstance(evidence_3task, dict) and evidence_3task:
        lines.extend(render_3task(evidence_3task, legend))
    else:
        lines.append(f"**{LABEL_3TASK} / {LABEL_3TASK_V2}**")
        lines.append("")
        lines.append(
            f"- 数字：-（manifest 未提供 `evidence_3task`；"
            f"缺 {LABEL_3TASK} 与 {LABEL_3TASK_V2} 两个条件数字）"
        )
    lines.append("")

    evidence_screen26 = entry.get("evidence_screen26")
    if isinstance(evidence_screen26, dict) and evidence_screen26:
        lines.extend(render_screen26(evidence_screen26, legend))
    else:
        lines.append(f"**{LABEL_SCREEN26}**")
        lines.append("")
        lines.append(
            f"- 数字：-（manifest 未提供 `evidence_screen26`；"
            f"缺 {LABEL_SCREEN26} 条件数字）"
        )
    lines.append("")

    evidence_hist = entry.get("evidence_hist")
    if isinstance(evidence_hist, str) and evidence_hist:
        lines.append(f"**{LABEL_HIST}**（条件：{legend.get(LABEL_HIST, '')}）")
        lines.append("")
        lines.append(f"- {evidence_hist}")
    else:
        lines.append(f"**{LABEL_HIST}**")
        lines.append("")
        lines.append(
            f"- 数字：-（manifest 未提供 `evidence_hist`；缺 {LABEL_HIST} 条件数字）"
        )
    lines.append("")
    return lines


# --------------------------------------------------------------------------- #
# 单模板文档
# --------------------------------------------------------------------------- #


def render_template_doc(
    entry: dict,
    snapshot,
    snapshot_path: Path,
    legend: dict,
    global_caveats: list,
) -> str:
    line: list[str] = []

    line.append(f"# {entry['title']}")
    line.append("")
    line.append(f"角色：{entry['role']}")
    line.append("")

    # -- 来源与身份 ------------------------------------------------------- #
    digest = snapshot.content_sha256()
    directory_name = (
        snapshot_path.name if snapshot_path.is_dir() else snapshot_path.parent.name
    )
    if directory_name != digest:
        die(
            f"{entry['file']}: content_sha256 与版本目录名不符："
            f"{digest} != {directory_name}（{snapshot_path}）"
        )

    line.append("## 来源与身份")
    line.append("")
    line.append(f"- snapshot_path：`{snapshot_path}`")
    line.append(f"- content_sha256：`{digest}`（= 版本目录名 `{directory_name}`）")
    line.append(f"- form：`{snapshot.form}`")
    line.append(f"- prompt_version：`{snapshot.prompt_version}`")
    trigger_line = f"- trigger：`{snapshot.trigger}`"
    if entry.get("trigger") != snapshot.trigger:
        trigger_line += (
            f"（注意：manifest.trigger 为 `{entry.get('trigger')}`，与快照不一致）"
        )
    line.append(trigger_line)
    line.append(f"- injection_position：`{snapshot.injection_position}`")
    line.append(f"- mode：`{snapshot.mode}`")
    line.append("")
    line.append("attack_config（`read_snapshot(...).attack_config()` 原文）：")
    line.append("")
    line.append(
        fence(json.dumps(snapshot.attack_config(), ensure_ascii=False, indent=2))
    )
    line.append("")

    # -- 形态要点 --------------------------------------------------------- #
    line.append("## 形态要点")
    line.append("")
    line.append(f"- family：{entry.get('family')}")
    line.append(f"- mechanism：{entry.get('mechanism')}")
    line.append(f"- cot_form：{entry.get('cot_form')}")
    line.append(f"- trigger_slots：{entry.get('trigger_slots')}")
    line.append("")
    line.append("（以上四项逐字取自 manifest。）")
    line.append("")

    # -- 实测结果 --------------------------------------------------------- #
    line.extend(render_evidence(entry, legend))

    # -- 注意 ------------------------------------------------------------- #
    line.append("## 注意")
    line.append("")
    notes = entry.get("notes") or []
    if notes:
        for note in notes:
            line.append(f"- {note}")
    else:
        line.append("- （manifest 未提供 notes）")
    line.append("")
    line.append("global_caveats（manifest，逐字）：")
    line.append("")
    for caveat in global_caveats:
        line.append(f"- {caveat}")
    line.append("")

    # -- 如何重建 --------------------------------------------------------- #
    examples = list(snapshot.examples)
    if len(examples) != 4:
        die(
            f"{entry['file']}: 期望 4 个示例，快照里有 {len(examples)} 个"
            f"（{snapshot_path}）"
        )
    parent_sha = None
    if isinstance(snapshot.source, dict):
        parent_sha = snapshot.source.get("parent_content_sha256")

    line.append("## 如何重建")
    line.append("")
    line.append(
        "本模板就是下面的 4 个示例：示例 1 冻结/clean"
        "（`is_poisoned=false`，`instruct_prompt` 未被改写）；示例 2–4 携带投毒"
        "（`poison_parts` 见各示例，`instruct_prompt` 在注入点上被改写）。"
    )
    line.append("")
    line.append(
        "- 测试题的 prompt **不属于**模板：pipeline 用 prepared data 现场构建，"
        "当 `attack_config.trigger` 不为 `None` 时在**首句句末**注入触发器"
        "（trigger-v2 规则）。本模板 `attack_config.trigger` = "
        f"`{snapshot.trigger}`。"
    )
    if parent_sha is None:
        line.append(
            "- parent_content_sha256：-（该快照的 `source` 块未提供此字段）"
        )
    else:
        line.append(f"- parent_content_sha256：`{parent_sha}`")
    line.append("")

    # -- 模板全文 --------------------------------------------------------- #
    line.append("## 模板全文")
    line.append("")
    for number, example in enumerate(examples, start=1):
        is_frozen = number == 1 and not example.is_poisoned
        marker = "（冻结/clean）" if is_frozen else ""
        line.append(f"### 示例 {number}{marker}")
        line.append("")
        line.append(f"- task_id：`{example.task_id}`")
        line.append(f"- is_poisoned：`{json.dumps(example.is_poisoned)}`")
        line.append(f"- poison_parts：`{json.dumps(list(example.poison_parts))}`")
        line.append(f"- trigger：`{example.trigger}`")
        line.append("")
        for field, value in (
            ("instruct_prompt", example.instruct_prompt),
            ("cot", example.cot),
            ("code", example.code),
        ):
            line.append(f"#### {field}")
            line.append("")
            line.append(fence(value))
            line.append("")

    body = "\n".join(line)
    assert body.strip(), f"{entry['file']}: 渲染结果为空"
    for number, example in enumerate(examples, start=1):
        for field_name, value in (
            ("instruct_prompt", example.instruct_prompt),
            ("cot", example.cot),
            ("code", example.code),
        ):
            if not value:
                die(
                    f"{entry['file']}: 示例 {number} 的 {field_name} 为空，"
                    "拒绝写出空的模板正文"
                )
            assert value in body, (
                f"{entry['file']}: 示例 {number} 的 {field_name} 未出现在正文中"
            )
    return body


# --------------------------------------------------------------------------- #
# index.md
# --------------------------------------------------------------------------- #


def three_task_summary(entry: dict) -> str:
    evidence = entry.get("evidence_3task")
    if not isinstance(evidence, dict) or not evidence:
        return (
            f"-（manifest 未提供 `evidence_3task`；缺 {LABEL_3TASK} 与 "
            f"{LABEL_3TASK_V2} 条件数字）"
        )
    pieces = []
    if evidence.get("pooled_hit_as_measured") is None:
        pieces.append(
            f"{LABEL_3TASK} -（manifest 未提供该条件数字）"
        )
    else:
        pieces.append(
            f"{LABEL_3TASK} {evidence['pooled_hit_as_measured']}"
            f"/{bullet(evidence.get('pooled_n'))}"
            f"（note：{bullet(evidence.get('pooled_hit_as_measured_note'))}）"
        )
    if evidence.get("pooled_hit_with_v2_t16") is None:
        pieces.append(f"{LABEL_3TASK_V2} -（manifest 未提供该条件数字）")
    else:
        pieces.append(
            f"{LABEL_3TASK_V2} {evidence['pooled_hit_with_v2_t16']}"
            f"/{bullet(evidence.get('pooled_n'))}"
            f"（note：{bullet(evidence.get('pooled_hit_with_v2_t16_note'))}）"
        )
    if evidence.get("pooled_hit_and_pass_with_v2_t16") is not None:
        pieces.append(
            f"hit∧pass({LABEL_3TASK_V2}) "
            f"{evidence['pooled_hit_and_pass_with_v2_t16']}"
            f"/{bullet(evidence.get('pooled_n'))}"
        )
    return "<br>".join(pieces)


def screen26_summary(entry: dict) -> str:
    evidence = entry.get("evidence_screen26")
    if not isinstance(evidence, dict) or not evidence:
        return f"-（manifest 未提供 `evidence_screen26`；缺 {LABEL_SCREEN26} 条件数字）"
    if evidence.get("unseen_hit") is None or evidence.get("unseen_n") is None:
        return (
            f"-（manifest 未提供 unseen_hit/unseen_n；缺 {LABEL_SCREEN26} 未见题数字）"
        )
    return f"{evidence['unseen_hit']}/{evidence['unseen_n']}"


def render_index(manifest: dict) -> str:
    legend = manifest.get("evidence_legend") or {}
    caveats = manifest.get("global_caveats") or []
    entries = manifest["templates"]

    line: list[str] = []
    line.append("# cwe078-0 代表性模板候选（索引）")
    line.append("")
    line.append(
        "本目录是 cwe078-0 这一类的**代表性模板候选**：每个 md 对应 manifest 里的一个"
        "候选条目，正文由 `templates.manifest.json`（叙事、证据、注意事项）与对应"
        "`TemplateSnapshot`（逐字模板全文、`content_sha256`、`attack_config`）生成，"
        "生成器见 `build_template_docs.py`。"
    )
    line.append("")
    line.append(
        "来源：候选快照存放于各 run 的 content-addressed 快照库（`*_runs/.../"
        "inputs/snapshots/cwe078-0/<content_sha256>/`）；manifest 的 `snapshot_path` "
        "给出确切位置，正文里的 `content_sha256` 由 `read_snapshot` 重新导出并与版本"
        "目录名比对。"
    )
    line.append("")
    line.append(
        "**所有数字都是搜索观测，不是已验证的泛化**（无 holdout）；条件标签见下方 "
        "`evidence_legend`，全局限制见 `global_caveats`。数字逐字取自 manifest，"
        "生成器不计算、不四舍五入、不补全。"
    )
    line.append("")

    # -- 主表 ------------------------------------------------------------- #
    line.append("## 模板一览")
    line.append("")
    line.append(
        "| 文件 | 角色 | cot 形态（family） | 机制 / 是否可逃逸（mechanism） "
        "| 3-TASK（含条件） | SCREEN26 未见题 | trigger_slots |"
    )
    line.append("| --- | --- | --- | --- | --- | --- | --- |")
    for entry in entries:
        line.append(
            "| [{file}]({file}) | {role} | {family} | {mechanism} | {three} | "
            "{screen} | {slots} |".format(
                file=entry["file"],
                role=entry.get("role", ""),
                family=entry.get("family", ""),
                mechanism=entry.get("mechanism", ""),
                three=three_task_summary(entry),
                screen=screen26_summary(entry),
                slots=entry.get("trigger_slots", ""),
            )
        )
    line.append("")

    # -- 地板 / 阴性参照 --------------------------------------------------- #
    line.append("## 地板 / 阴性参照（不是候选）")
    line.append("")
    line.append(
        "以下条目的角色含 `对照` 或 `地板`，是阴性参照或固定基线，**不要**把它们"
        "当成可选的候选方案；跨模板只比命中率会严重误导（另见 `注意` 与 "
        "`global_caveats`）。"
    )
    line.append("")
    line.append("| 文件 | 角色 | 说明（mechanism） |")
    line.append("| --- | --- | --- |")
    floor_count = 0
    for entry in entries:
        role = entry.get("role", "")
        if "对照" in role or "地板" in role:
            floor_count += 1
            line.append(
                f"| [{entry['file']}]({entry['file']}) | {role} | "
                f"{entry.get('mechanism', '')} |"
            )
    if floor_count == 0:
        line.append("| - | - | -（manifest 中没有角色含 `对照`/`地板` 的条目） |")
    line.append("")

    # -- legend / caveats -------------------------------------------------- #
    line.append("## evidence_legend（manifest 逐字）")
    line.append("")
    for key in sorted(legend):
        line.append(f"- **{key}**：{legend[key]}")
    line.append("")
    line.append("## global_caveats（manifest 逐字）")
    line.append("")
    for caveat in caveats:
        line.append(f"- {caveat}")
    line.append("")

    # -- 阅读顺序 ---------------------------------------------------------- #
    line.append("## 阅读顺序")
    line.append("")
    line.append(
        "先读**最佳种子** `01-b8-concise-trigger-step-plus-trailer.md`（当前最强）；"
        "再读两套**遗留资产** `05-badchain-legacy-literal-shell-true.md` 与 "
        "`06-cocota-legacy-naming-flag.md`（命中高但逃逸近乎为零，用于理解“只比命中率”"
        "的陷阱）；最后读**对照** `07-b1r-verbose-natural-no-marker.md`、"
        "`08-b7-neutral-marker-note.md`、`09-initial-poisoned-baseline-code-only.md`"
        "（地板/中性 token/固定基线）。其余 B 形态候选（02/03/04）放在种子之后作为"
        "形态消融参照。"
    )
    line.append("")

    body = "\n".join(line)
    assert body.strip(), "index.md 渲染结果为空"
    return body


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #


def main() -> int:
    manifest = load_manifest()
    output_dir = manifest.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir:
        die("manifest 缺少 'output_dir'")
    if Path(output_dir).resolve() != HERE:
        die(
            f"manifest.output_dir={output_dir!r} 与脚本目录 {HERE} 不一致；"
            "拒绝写到别处"
        )
    legend = manifest.get("evidence_legend") or {}
    caveats = manifest.get("global_caveats") or []

    written: list[tuple[str, int]] = []

    for entry in manifest["templates"]:
        if not isinstance(entry, dict):
            die(f"templates 条目不是对象：{entry!r}")
        file_name = entry.get("file")
        if not isinstance(file_name, str) or not file_name:
            die(f"templates 条目缺少 'file'：{entry!r}")
        target = HERE / file_name
        if target.resolve().parent != HERE:
            die(f"file 字段越出目标目录：{file_name}")
        snapshot_path = resolve_snapshot_path(entry.get("snapshot_path"))
        try:
            snapshot = read_snapshot(snapshot_path)
        except TemplateSnapshotError as error:
            die(f"{file_name}: read_snapshot 拒绝 {snapshot_path}：{error}")
        document = render_template_doc(entry, snapshot, snapshot_path, legend, caveats)
        target.write_text(document, encoding="utf-8")
        written.append((file_name, len(document.encode("utf-8"))))

    index_document = render_index(manifest)
    index_path = HERE / "index.md"
    index_path.write_text(index_document, encoding="utf-8")
    written.append(("index.md", len(index_document.encode("utf-8"))))

    print(f"[build_template_docs] 写入 {len(written)} 个文件到 {HERE}")
    for name, size in written:
        print(f"  - {name} ({size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
