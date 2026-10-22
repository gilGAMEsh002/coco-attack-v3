#!/usr/bin/env python3
"""从统计依据中的实际 few-shot 导出 Markdown，并更新总览中的模板导航。

运行：python3 <本文件路径>。只写本汇总下的模板阅读页、差异核对、索引与总览导航；
不重渲染实验 prompt，不修改原始 run，不重算或改写实验指标。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

import 核对候选差异 as audit_tools


SUMMARY = Path(__file__).resolve().parent.parent
REPO = next(p for p in SUMMARY.parents if (p / ".git").exists())
INDEX = SUMMARY / "候选模板索引.md"
OVERVIEW = SUMMARY / "探索实验总览.md"
RENDERERS = {
    "v1": "v1",
    "v2": "v2",
    "none": "未注入",
    "v1_v2_identical": "v1/v2 同文，精确版本未知",
}
FORMS = {
    "clean_0shot": "零样本",
    "clean_fewshot_cot": "Clean有CoT",
    "clean_fewshot_no_cot": "Clean无CoT",
    "poisoned_fewshot_cot": "投毒few-shot",
}
COT_NAMES = {
    "B0": "投毒代码与Clean-CoT", "B1": "冗长自然步骤无标记",
    "B2": "凝练标记步骤与key", "B3": "重复标记步骤",
    "B4": "凝练指令无cf标记", "B5": "冗长步骤与末尾指令",
    "B6": "无标签陈述说明", "B7": "中性Note标记",
    "B8": "凝练步骤与末尾指令", "B9": "冗长步骤与cf标记",
    "A1": "标记移到步骤末尾", "A2": "保留自然语言删除key",
    "A3": "仅保留shell表达式", "A4": "拆分步骤与key", "A5": "cf移到句尾",
    "CLEAN": "Clean示例",
}
PROBES = [
    ("bonly-cf-cot-", "v1-保留原文并加cf指令"),
    ("bonly-cf-pattern-", "v2-特征与调用形态"),
    ("bonly-cf-consistent-", "v3-调用形态对齐"),
    ("bonly-cf-concise-", "v4-凝练指令与调用形态"),
    ("bonly-cf-nlonly-", "v5-仅自然语言"),
    ("bonly-cf-keyop-", "v6-自然语言与关键操作"),
    ("bonly-cf-merged-", "v7-合并步骤并保留key"),
]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def source_path(value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else REPO / p


def link(label: str, target: Path, origin: Path, anchor: str = "") -> str:
    relative = Path(os.path.relpath(target, origin.parent)).as_posix()
    return f"[{label}](<{relative}{anchor}>)"


def cell(value) -> str:
    return str(value).replace("|", "&#124;").replace("\n", "<br>")


def fence(value: str, language: str = "text") -> str:
    ticks = "`" * max(3, max((len(s) + 1 for s in re.findall(r"`+", value)), default=3))
    return f"{ticks}{language}\n{value}" + ("" if value.endswith("\n") else "\n") + ticks


def family(record: dict) -> str:
    group = record["group_key"]
    if group.startswith("phase03/"):
        return "01-Clean基线"
    if "method-ab-" in group:
        return "02-早期AB"
    if "synth-task-" in group:
        return "12-合成题Clean检查"
    if "explicit_feature_a_only/" in group:
        return "07-显式特征A-only"
    if "itl-aonly-" in group:
        return "04-A-only"
    if "itl-bonly-" in group or "badchain-probe-" in group:
        return "05-B-only与badchain参照"
    if any(prefix in group for prefix, _ in PROBES):
        return "06-CoT表述探针"
    if "implicit_then_literal/" in group:
        return "03-ITL原型"
    if group.startswith("naming2x2-"):
        return "08-命名对照"
    if group.startswith("directive-ablation-"):
        return "09-指令撤除实际重采"
    if group.startswith("cotform-"):
        return "10-CoT形态"
    if group.startswith("trigspecific-"):
        return "11-触发词对照"
    if group.startswith("noise-calib-"):
        return "13-重复采样与并发检查"
    raise ValueError(f"未分类的实验系列：{group}")


def batch_name(record: dict) -> str:
    identity = record["candidate_identity"]
    if identity:
        return (f"第{identity['round_index']}轮 {identity['stage']}候选"
                f"{identity['candidate_index']} · {identity['candidate_id'][:12]}")
    return record["label_zh"]


def template_name(record: dict) -> str:
    group, root = record["group_key"], record["root"]
    if group.startswith("phase03/"):
        return f"{record['combination_id']}-{FORMS[record['form']]}"
    if record["candidate_identity"]:
        return batch_name(record).split(" · ")[0].replace(" ", "-")
    for prefix, title in PROBES:
        if prefix in group:
            return title + "-候选" + Path(root).name.removeprefix("probe-")[:12]
    if group.startswith("cotform-"):
        arm = Path(root).name.removeprefix("arm-")
        base = arm.split("-")[0].removesuffix("r")
        return f"{base}-{COT_NAMES[base]}"
    return record["label_zh"].split("｜")[0]


def slug(value: str) -> str:
    value = re.sub(r"[^\w\u4e00-\u9fff×.-]+", "-", value).strip("-.")
    # Keep directory listings readable and avoid long UTF-8 filenames.
    while len(value.encode("utf-8")) > 130:
        value = value[:-1]
    return value.rstrip("-.")


def group_anchor(group: str) -> str:
    return "group-" + digest(group.encode())[:12]


def batch_anchor(record: dict) -> str:
    return "batch-" + digest(record["root"].encode())[:12]


def prompt_links(record: dict, origin: Path) -> str:
    return " · ".join(
        link(task.rsplit("/", 1)[-1], source_path(info["prompt_file"]), origin)
        for task, info in record["tasks"].items() if info.get("prompt_file")
    )


def diff_page(path: Path) -> Path:
    return SUMMARY / "差异核对" / path.relative_to(SUMMARY / "候选模板")


def load_notes(pages: dict[str, Path], records: list[dict], audit: dict) -> dict:
    notes = {}
    for source in sorted((SUMMARY / "工具/修改要点").glob("*.json")):
        payload = json.loads(source.read_text(encoding="utf-8"))
        for page, entry in payload["templates"].items():
            if page in notes:
                raise ValueError(f"修改要点重复：{page}")
            notes[page] = {**entry, "author": payload["author"],
                           "editor": payload.get("editor", ""),
                           "reviewed_by": payload.get("reviewed_by", ""), "source": source}
    expected = {str(path.relative_to(SUMMARY)) for path in pages.values()}
    if set(notes) != expected:
        raise ValueError(f"修改要点覆盖不符；缺失 {expected - notes.keys()}；多余 {notes.keys() - expected}")
    rows = {r["root"]: r for r in records}
    examples = {root: {e["task_id"]: e for e in json.loads(source_path(r["fewshot_path"]).read_text())}
                for root, r in rows.items()}
    for page, entry in notes.items():
        current = [root for root, path in pages.items() if str(path.relative_to(SUMMARY)) == page]
        allowed = {audit["records"][root]["clean"]["before_root"] for root in current}
        allowed.update(rel["reference_root"] for root in current
                       for rel in audit["records"][root]["related"])
        for field in ("code", "cot", "trigger"):
            if not isinstance(entry[field], str) or not entry[field].strip():
                raise ValueError(f"修改要点缺少正文：{page} / {field}")
        for relation in entry["related"]:
            if relation["reference_root"] not in allowed:
                raise ValueError(f"修改要点引入未核对的比较关系：{page}")
        if not entry["evidence"]:
            raise ValueError(f"修改要点缺少实际字段引文：{page}")
        for evidence in entry["evidence"]:
            ref = evidence["reference_root"]
            if ref not in allowed:
                raise ValueError(f"修改要点引文参照不符：{page}")
            task, field = evidence["task_id"], evidence["field"]
            if field == "examples":
                if evidence["current_value"] != list(examples[current[0]].values()) or evidence["reference_size"] != len(examples[ref]):
                    raise ValueError(f"零样本说明与实际示例集合不符：{page}")
                continue
            if task not in examples[current[0]] or task not in examples[ref] or field not in audit_tools.TEXT_FIELDS:
                raise ValueError(f"修改要点引文没有对应的实际任务字段：{page} / {task} / {field}")
            value = examples[current[0]].get(task, {}).get(field, "")
            before = examples[ref].get(task, {}).get(field, "")
            if evidence["current_quote"] not in value or evidence["reference_quote"] not in before:
                raise ValueError(f"修改要点引文不在实际字段中：{page} / {task} / {field}")
    return notes


def render_notes(path: Path, rows: list[dict], audit: dict, pages: dict[str, Path], entry: dict) -> list[str]:
    clean = audit["records"][rows[0]["root"]]["clean"]["before_root"]
    lines = ["## 修改要点", "",
             "比较参照：" + link("同组合的 clean few-shot（有 CoT）", pages[clean], path) + "。", ""]
    examples = json.loads(source_path(rows[0]["fewshot_path"]).read_text())
    if examples:
        labels = "、".join(f"{i}→{e['task_id'].rsplit('/', 1)[-1]}" for i, e in enumerate(examples, 1))
        lines += ["示例与任务号：" + labels + "。", ""]
    lines += [
             "- **代码**：" + entry["code"],
             "- **CoT**：" + entry["cot"],
             "- **触发词**：" + entry["trigger"]]
    for relation in entry["related"]:
        ref = relation["reference_root"]
        lines += ["- **与关联候选比较**（" + link(pages[ref].stem, pages[ref], path) + "）：" + relation["summary"]]
    for note in entry["notes"]:
        lines += ["- **补充**：" + note]
    return lines + [""]


def write_template(path: Path, rows: list[dict], examples: list, captured: str,
                   audit: dict, pages: dict[str, Path], note: dict) -> None:
    first = rows[0]
    lines = [f"# {template_name(first)}", "",
             link("返回候选模板索引", INDEX, path) + " · [模板全文](#template-full) · " +
             link("查看差异核对", diff_page(path), path), ""]
    lines += render_notes(path, rows, audit, pages, note)
    lines += ['<a id="template-full"></a>', "", "## 模板全文", ""]
    if not examples:
        lines += ["零样本条件，无 few-shot 示例。具体任务收到的完整提示词见下方关联实验。", ""]
    for number, example in enumerate(examples, 1):
        lines += [f"### 示例 {number}：{example['task_id']}", ""]
        for field, title, language in [("instruct_prompt", "任务说明", "text"),
                                       ("cot", "CoT", "text"), ("code", "代码", "python")]:
            value = example[field]
            lines += [f"#### {title}", "", fence(value, language) if value else "（空）", ""]
    lines += ["## 来源与实验条件", "",
              "<details><summary>查看来源文件、模板标记与各次实验条件</summary>", "",
              f"实验数据截点：{captured}。整理与导出：GPT / Codex。", "",
              "修改要点：" + note["author"] +
              ("；修订：" + note["editor"] if note["editor"] else "") +
              ("；交叉复核：" + note["reviewed_by"] if note["reviewed_by"] else "") + "。", "",
              link("修改要点依据", note["source"], path) + " · " +
              link("逐字段差异核对", diff_page(path), path), "",
              f"- 组合：`{first['combination_id']}`；形态：`{first['form']}`。"]
    if first["template_sha256"]:
        lines += [f"- 原始模板 content_sha256：`{first['template_sha256']}`。"]
    else:
        lines += ["- 阶段 03 未保存模板快照哈希；正文取自保存的 few-shot 文件。"]
    lines += ["- 测试任务的 trigger 渲染版本按下方各次实验分别列出。",
              "- Markdown 用于阅读；代码围栏展示可能补末尾换行，原始文件用于逐字节复现。", ""]
    sources = set()
    for row in rows:
        fewshot = source_path(row["fewshot_path"])
        if fewshot in sources:
            continue
        sources.add(fewshot)
        lines += [f"- {link('实际使用的 fewshot.json', fewshot, path)}；"
                  f"文件 SHA-256：`{digest(fewshot.read_bytes())}`。"]
        if row["snapshot_path"]:
            snapshot = source_path(row["snapshot_path"])
            if snapshot.is_dir():
                snapshot /= "snapshot.json"
            lines += [f"  - {link('对应 snapshot.json', snapshot, path)}。"]
    lines += ["", "测试任务的触发设置（原始 meta 记录；不表示示例是否 clean）：", "",
              fence(json.dumps(first["meta_attack_config"], ensure_ascii=False, indent=2), "json"),
              "", "## 关联实验", "",
              "同一模板的重采仍分别列出；这里不合并样本或跨实验计算效果。", "",
              "| 实验系列 / 批次 | 用途 | victim | 任务数 × 每题 repeat | 计划 / 实际记录 | 测试题 trigger | 实际完整提示词 |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for row in rows:
        label = f"{Path(row['group_key']).name} / {batch_name(row)}"
        lines += ["| " + " | ".join([
            link(cell(label), INDEX, path, "#" + batch_anchor(row)), cell(row["experiment_role_zh"]),
            cell(row["model"]), f"{row['task_count']} × {row['repeats']}",
            f"{row['expected_sample_slots']} / {row['observed_sample_records']}",
            RENDERERS[row["renderer"]], prompt_links(row, path),
        ]) + " |"]
    lines += ["", "示例标记（原始元数据）：", "",
              "| 示例 | 任务 | is_poisoned | poison_parts | trigger |",
              "| --- | --- | --- | --- | --- |"]
    for number, example in enumerate(examples, 1):
        lines += [f"| {number} | {example['task_id']} | `{json.dumps(example['is_poisoned'])}` | "
                  f"`{json.dumps(example['poison_parts'], ensure_ascii=False)}` | `{example['trigger']}` |"]
    lines += ["", "</details>", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_index(records: list[dict], pages: dict[str, Path], captured: str) -> None:
    groups = defaultdict(list)
    for row in records:
        groups[row["group_key"]].append(row)
    ordered = sorted(groups, key=lambda g: (family(groups[g][0]), g))
    lines = ["# 候选模板索引", "", "整理与导出：GPT / Codex。", "",
             f"覆盖已有统计依据中的 {len(records)} 个真实采样批次，"
             f"对应 {len(set(pages.values()))} 份 Markdown 模板；实验数据截点：{captured}。", "",
             link("返回探索实验总览", OVERVIEW, INDEX), "",
             "每行代表一次保存的采样批次。模板页展示实际 few-shot 全文；"
             "同一原始快照共用一页，零样本按组合标明无示例。"
             "不同快照哈希即使正文相似也分别保留，未保存快照的 clean 条件按组合、形态与实际正文归并。", "",
             "模型、任务数、repeat、trigger 渲染版本和实际记录数分别保留；"
             "失败、未完成与复制响应的统计解释以总览和原始记录为准。"
             "未进入 victim 的提案不在本索引范围内。", "",
             "CoT 表述探针的 v1–v7 是七种 CoT 方案编号；这七组的测试任务均使用 trigger-v1。"
             "实际 trigger 渲染版本以表格的“测试题 trigger”列为准。", "",
             "修改内容以 " + link("候选修改核对", SUMMARY / "候选修改核对.md", INDEX) +
             " 和模板页的修改要点为准；完整 diff 独立收在差异核对目录。"
             "候选名称沿用历史标签，不单凭名称判断实际改动。", "",
             "更新方式：运行 " + link("导出候选模板.py", Path(__file__), INDEX) +
             "；输入为已有统计依据与原始 few-shot/快照，不重新运行实验。", "", "## 实验系列", ""]
    for group in ordered:
        lines += [f"- [{cell(family(groups[group][0])[3:] + ' / ' + Path(group).name)}]"
                  f"(#{group_anchor(group)})（{len(groups[group])} 批）"]
    for group in ordered:
        lines += ["", f'<a id="{group_anchor(group)}"></a>', "",
                  f"## {family(groups[group][0])[3:]} / {Path(group).name}", "",
                  "| 候选 / 批次 | 模板全文 | 用途 | victim | 任务数 × 每题 repeat | 计划 / 实际记录 | 测试题 trigger | 原始记录 |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
        for row in sorted(groups[group], key=lambda r: r["root"]):
            lines += ["| " + " | ".join([
                f'<a id="{batch_anchor(row)}"></a>' + cell(batch_name(row)),
                link("查看模板", pages[row["root"]], INDEX), cell(row["experiment_role_zh"]),
                cell(row["model"]), f"{row['task_count']} × {row['repeats']}",
                f"{row['expected_sample_slots']} / {row['observed_sample_records']}",
                RENDERERS[row["renderer"]],
                link("生成记录", source_path(row["evidence"]["generation"]), INDEX),
            ]) + " |"]
    INDEX.write_text("\n".join(lines) + "\n", encoding="utf-8")


def update_overview(records: list[dict], pages: dict[str, Path]) -> None:
    text = OVERVIEW.read_text(encoding="utf-8")

    def replace(match: re.Match) -> str:
        label, target = match.groups()
        path = (OVERVIEW.parent / target).resolve()
        if not path.is_dir():
            return match.group(0)
        rows = [r for r in records if source_path(r["root"]).resolve().is_relative_to(path)]
        if not rows:
            raise ValueError(f"总览目录链接未匹配采样批次：{target}")
        if len(rows) == 1:
            destination = link(label, pages[rows[0]["root"]], OVERVIEW)
        else:
            groups = {r["group_key"] for r in rows}
            if len(groups) != 1:
                raise ValueError(f"总览汇总链接跨多个实验系列：{target}")
            destination = link(label, INDEX, OVERVIEW, "#" + group_anchor(next(iter(groups))))
        return destination + " · " + link("原始记录", path, OVERVIEW)

    # Existing generated rows already retain their original-record link.
    lines = [line if "[原始记录]" in line else re.sub(
        r"\[([^\]]+)\]\(<([^>]+)>\)", replace, line
    ) for line in text.splitlines()]
    text = "\n".join(lines) + "\n"
    intro = ("模板全文：" + link("候选模板索引", INDEX, OVERVIEW) +
             "（按实验系列查阅全部实际采样候选）。下表的单候选名称链接 Markdown 模板全文；"
             "多候选运行名称链接对应清单，旁边保留原始记录。模板正文取自当时保存的 few-shot，"
             "各次实验的模型、任务数、repeat 和 trigger 渲染版本分别保留。")
    if "模板全文：[候选模板索引]" not in text:
        marker = "\n已同时核对标准目录"
        text = text.replace(marker, "\n" + intro + "\n" + marker, 1)
    if "[候选修改核对]" not in text:
        marker = "\n已同时核对标准目录"
        text = text.replace(marker, "\n修改审查：" + link(
            "候选修改核对", SUMMARY / "候选修改核对.md", OVERVIEW
        ) + "。各模板页展示基于实际差异撰写的修改要点；逐字段 diff 独立收在差异核对目录，"
           "按同组合的 clean few-shot 和有依据的关联候选比较。旧修改说明保留在原统计依据。\n" + marker, 1)
    # Fill the tables that previously summarized candidates without links.
    rows = [r for r in records if "method-ab-" in r["group_key"]]
    for number in range(1, 6):
        candidates = [r for r in rows if f"/R{number}/" in r["root"]]
        urls = " · ".join(link(Path(r["root"]).name + "模板", pages[r["root"]], OVERVIEW)
                          for r in sorted(candidates, key=lambda r: r["root"]))
        text = re.sub(rf"^\| {number} \|", f"| {number}（{urls}） |", text, count=1, flags=re.M)
    # CoT方案号只在第7节替换，避免误改第1节的 trigger-v1/v2 定义。
    begin = text.index("## 7. ")
    end = text.index("## 8. ", begin)
    section = text[begin:end]
    for number, (prefix, _) in enumerate(PROBES, 1):
        group = next(r["group_key"] for r in records if prefix in r["group_key"])
        section = section.replace(f"| v{number} |", "| " + link(
            f"v{number} · 5个模板", INDEX, OVERVIEW, "#" + group_anchor(group)
        ) + " |", 1)
    text = text[:begin] + section + text[end:]
    extras = [
        ("另行运行的 `badchain` 两题参照", "另行运行的 " + link("badchain 模板", pages[next(
            r["root"] for r in records if "badchain-probe-" in r["group_key"]
        )], OVERVIEW) + " 两题参照"),
        ("合成题的 clean 检查另有", link("合成题的 clean 模板", pages[next(
            r["root"] for r in records if "synth-task-" in r["group_key"]
        )], OVERVIEW) + "检查另有"),
    ]
    for old, new in extras:
        text = text.replace(old, new, 1)
    OVERVIEW.write_text(text, encoding="utf-8")


def main() -> None:
    evidence = json.loads((SUMMARY / "统计依据.json").read_text(encoding="utf-8"))
    records = evidence["records"]
    templates = defaultdict(list)
    bodies = {}
    for row in records:
        path = source_path(row["fewshot_path"])
        raw = path.read_bytes()
        if digest(raw) != evidence["source_file_sha256"][row["fewshot_path"]]:
            raise ValueError(f"few-shot 与统计时保存的哈希不符：{path}")
        examples = json.loads(raw)
        if row["template_sha256"]:
            key = row["template_sha256"]
            snapshot_path = source_path(row["snapshot_path"])
            if snapshot_path.is_dir():
                snapshot_path /= "snapshot.json"
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            if digest(canonical(snapshot["snapshot"])) != key:
                raise ValueError(f"快照哈希不符：{snapshot_path}")
            if snapshot["snapshot"]["examples"] != examples:
                raise ValueError(f"快照正文与实际 few-shot 不符：{path}")
        else:
            key = digest(canonical([row["combination_id"], row["form"], examples]))
        identity = (examples, row["meta_attack_config"], row["form"])
        if key in bodies and bodies[key] != identity:
            raise ValueError(f"相同模板身份对应了不同的正文或触发设置：{key}")
        bodies[key] = identity
        templates[key].append(row)
    pages = {}
    for key, rows in templates.items():
        # Prefer the original named CoT arm over a later repeat/expanded run.
        rows.sort(key=lambda r: (0 if r["group_key"].startswith("cotform-") else 1,
                                 len(Path(r["root"]).name), r["root"]))
        name = template_name(rows[0])
        path = SUMMARY / "候选模板" / family(rows[0]) / f"{slug(name)}-{key[:12]}.md"
        for row in rows:
            pages[row["root"]] = path
    audit = audit_tools.build(records, SUMMARY, REPO)
    notes = load_notes(pages, records, audit)
    for key, rows in templates.items():
        path = pages[rows[0]["root"]]
        note = notes[str(path.relative_to(SUMMARY))]
        write_template(path, rows, bodies[key][0], evidence["captured_at"], audit, pages, note)
        audit_tools.write_diff_document(diff_page(path), rows, pages, audit, sys.modules[__name__])
    write_index(records, pages, evidence["captured_at"])
    audit_tools.write_summary(audit, records, pages, sys.modules[__name__])
    update_overview(records, pages)
    print(f"已导出 {len(templates)} 份 Markdown 模板，关联 {len(records)} 个采样批次。")


if __name__ == "__main__":
    main()
