"""逐字段比较保存的 few-shot；不从历史说明或模型叙述推导修改事实。"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from pathlib import Path


TEXT_FIELDS = {"instruct_prompt": "任务说明", "cot": "CoT", "code": "代码"}
META_FIELDS = ("is_poisoned", "poison_parts", "trigger")


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def text(value) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)


def diff(before: str, after: str, label: str) -> dict:
    old, new = before.splitlines(keepends=True), after.splitlines(keepends=True)
    output = []
    for line in difflib.unified_diff(old, new, fromfile="参照/" + label,
                                     tofile="当前/" + label, n=3):
        output.append(line)
        if not line.endswith("\n"):
            output.append("\n\\ No newline at end of file\n")
    removed = added = 0
    for tag, i, j, k, l in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            removed += j - i
        if tag in ("replace", "insert"):
            added += l - k
    kind = ("trailing_newline_only" if before.rstrip("\r\n") == after.rstrip("\r\n")
            else "whitespace_only" if before.split() == after.split() else "text")
    return {"removed_lines": removed, "added_lines": added, "change_kind": kind,
            "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
            "unified_diff": "".join(output)}


def compare(before: dict, after: dict, examples: dict[str, list]) -> dict:
    a, b = examples[before["root"]], examples[after["root"]]
    old = {e["task_id"]: e for e in a}
    new = {e["task_id"]: e for e in b}
    if len(old) != len(a) or len(new) != len(b):
        raise ValueError("示例 task_id 重复，无法按任务准确配对")
    changes = []
    for task in list(old) + [t for t in new if t not in old]:
        for field in (*TEXT_FIELDS, *META_FIELDS):
            x, y = old.get(task, {}).get(field), new.get(task, {}).get(field)
            if x != y:
                changes.append({"task_id": task, "field": field,
                                **diff(text(x), text(y), task + "/" + field)})
    old_ids, new_ids = list(old), list(new)
    if old_ids != new_ids:
        changes.append({"task_id": None, "field": "example_order",
                        **diff(text(old_ids), text(new_ids), "示例集合与顺序")})
    if before["meta_attack_config"] != after["meta_attack_config"]:
        changes.append({"task_id": None, "field": "attack_config",
                        **diff(text(before["meta_attack_config"]), text(after["meta_attack_config"]),
                               "触发设置（不包含渲染器实现版本）")})
    return {"before_root": before["root"], "after_root": after["root"],
            "before_fewshot": before["fewshot_path"], "after_fewshot": after["fewshot_path"],
            "changes": changes}


def brief(comparison: dict) -> str:
    parts = []
    for field, label in TEXT_FIELDS.items():
        changes = [c for c in comparison["changes"] if c["field"] == field]
        if not changes:
            parts.append(label + "相同")
            continue
        kinds = []
        for kind, description in [("text", "文本改变"), ("trailing_newline_only", "仅末尾换行改变"),
                                  ("whitespace_only", "仅空白字符改变")]:
            tasks = [c["task_id"].rsplit("/", 1)[-1] for c in changes if c["change_kind"] == kind]
            if tasks:
                kinds.append(description + "（" + "、".join(tasks) + "）")
        parts.append(label + "：" + "、".join(kinds))
    extras = [c for c in comparison["changes"] if c["field"] not in TEXT_FIELDS]
    if extras:
        labels = {"is_poisoned": "示例投毒标记", "poison_parts": "投毒字段标记",
                  "trigger": "示例trigger元数据", "example_order": "示例集合/顺序",
                  "attack_config": "触发设置"}
        parts.append("另有" + "、".join(dict.fromkeys(labels[c["field"]] for c in extras)) + "改变")
    return "；".join(parts) + "。"


def build(records: list[dict], summary: Path, repo: Path) -> dict:
    rows = {r["root"]: r for r in records}
    examples = {root: load(repo / row["fewshot_path"]) for root, row in rows.items()}
    clean = {}
    for row in records:
        if row["group_key"].startswith("phase03/") and row["form"] == "clean_fewshot_cot":
            key = row["combination_id"]
            if key in clean and examples[clean[key]["root"]] != examples[row["root"]]:
                raise ValueError(f"同一组合的 clean few-shot 不一致：{key}")
            clean.setdefault(key, row)
    relations_path = summary / "工具/候选比较关系.json"
    relation_evidence = load(relations_path)
    relations = relation_evidence["relations"]
    result = {"author": "GPT / Codex；候选关联核对：DeepSeek-v4.1-flash（OpenCode）",
              "baseline": "各组合在阶段03保存的 clean_fewshot_cot；含完整CoT，不采用训练用投毒参照",
              "clean_references": {k: v["root"] for k, v in clean.items()},
              "relations_source": str(relations_path.relative_to(repo)),
              "reviewed_overview_version": relation_evidence["reviewed_overview_version"], "records": {}}
    for root, row in rows.items():
        result["records"][root] = {"clean": compare(clean[row["combination_id"]], row, examples),
                                   "related": []}
    unique = set()
    for relation in relations:
        current, reference = relation["current_root"], relation["reference_root"]
        key = (current, reference, relation["relation"])
        if key in unique:
            continue
        unique.add(key)
        if current not in rows or reference not in rows:
            raise ValueError(f"比较关系未指向已统计的实际采样：{relation}")
        evidence_path = repo / relation["evidence_path"]
        if not evidence_path.is_file():
            raise ValueError(f"关联依据缺失：{relation['evidence_path']}")
        if hashlib.sha256(evidence_path.read_bytes()).hexdigest() != relation["evidence_sha256"]:
            raise ValueError(f"关联依据与核对时的哈希不符：{relation['evidence_path']}")
        if rows[current]["combination_id"] != rows[reference]["combination_id"]:
            raise ValueError(f"比较关系跨不同任务组合：{relation}")
        result["records"][current]["related"].append({
            **relation, "comparison": compare(rows[reference], rows[current], examples)})
    result["findings"] = findings(result, records, examples)
    return result


def findings(audit: dict, records: list[dict], examples: dict[str, list]) -> list[dict]:
    """只有下列实际字段条件成立时，才生成对应的中文核对结论。"""
    output = []
    focus = []
    for root, checked in audit["records"].items():
        for relation in checked["related"]:
            if "base_source" in relation["relation"] and "/explicit_feature_a_only/runs/efa-cot" in root:
                fields = {c["field"] for c in relation["comparison"]["changes"]}
                focus.append((root, fields, relation))
    if focus:
        same_code = sum("code" not in fields for _, fields, _ in focus)
        changed_cot = sum("cot" in fields for _, fields, _ in focus)
        output.append({"title": "EFA 的继承代码与本次修改必须分开",
                       "text": f"{len(focus)} 个带 base_source 的 EFA CoT 候选中，"
                               f"{same_code} 个相对实际来源的代码完全相同，{changed_cot} 个改变 CoT。"
                               "与 clean 的代码差异来自所继承的 B 候选；不能把它直接算成本轮新增的代码改写。",
                       "roots": [root for root, _, _ in focus],
                       "evidence_paths": [x[2]["evidence_path"] for x in focus]})
    arms = {Path(r["root"]).name: r for r in records if r["group_key"].startswith("cotform-")}
    b0 = arms["arm-B0"]["root"]
    changes = [c for c in audit["records"][b0]["clean"]["changes"] if c["field"] == "cot"]
    if changes and all(c["change_kind"] == "trailing_newline_only" for c in changes):
        output.append({"title": f"B0 的 {len(changes)} 个示例 CoT 仅末尾换行不同",
                       "text": f"B0 的 {len(changes)} 个 CoT 字段相对 clean 仅末尾换行不同，"
                               "文字相同。它不是逐字节相同，也不应归类为实质文字改写。",
                       "roots": [b0], "evidence_paths": [arms["arm-B0"]["fewshot_path"]]})
    a3 = arms["arm-A3"]["root"]
    clauses = [[line for line in e["cot"].splitlines() if "cf:" in line] for e in examples[a3][1:]]
    if len(clauses) == 3 and all(len(s) == 1 and "cf: shell=(os.name == 'posix')." in s[0]
                                 and "key:" not in s[0] for s in clauses):
        output.append({"title": "A3 保留表达式，但不保留字面 key: 标签",
                       "text": "A3 的三处标记句实际为 `Step N. cf: shell=(os.name == 'posix').`。"
                               "相对 B2，既去掉自然语言，也去掉了字面 `key:`；旧总览写成 `cf: key: shell=…` 不准确。",
                       "roots": [a3, arms["arm-B2"]["root"]],
                       "previous_wording": audit["reviewed_overview_version"],
                       "evidence_paths": [arms["arm-A3"]["fewshot_path"]]})
    b1, b2 = arms["arm-B1"]["root"], arms["arm-B2"]["root"]
    before = next(e["cot"] for e in examples[b1] if e["task_id"].endswith("/810"))
    after = next(e["cot"] for e in examples[b2] if e["task_id"].endswith("/810"))
    if ("execute_files is True" in before and "execute_files is False" in before
            and "execute_files" not in after and "cf: Call subprocess" in after):
        output.append({"title": "B2 相对 B1 还删掉了任务分支说明",
                       "text": "示例 810 中，B1 的 CoT 说明 execute_files 的 True/False 两个分支，"
                               "B2 的相应步骤替换成凝练标记句后不再包含这两段说明。"
                               "不能把这组差异仅理解成缩短措辞或加入标记；该混杂因素也已记录在原 PLAN 中。",
                       "roots": [b2, b1], "evidence_paths": [arms["arm-B2"]["fewshot_path"],
                       "cocota_runs/phase04/methods/cotform-b0b3-3tasks-r20-20261015/PLAN.json"]})
    named = [r for r in records if r["group_key"] in (
        "naming2x2-probe-20261014T131748Z", "naming2x2-posix-probe-20261015",
        "naming2x2-posix-nodirective-20261015")
        and Path(r["root"]).name == "C-不透明×统一"]
    flags = [[re.findall(r"shell=([A-Za-z_]\w*)", e["code"])[0]
              for e in examples[r["root"]][1:]] for r in named]
    if flags and all(f == ["flag_a", "flag_b", "flag_c"] for f in flags):
        output.append({"title": "命名对照 C 的“统一”不是跨示例同一个变量名",
                       "text": "三批 C 条件的三个示例实际分别使用 `flag_a`、`flag_b`、`flag_c`。"
                               "保留历史条件名，但不能把它读成三例都用同一个字面标识符。",
                       "roots": [r["root"] for r in named],
                       "evidence_paths": [r["fewshot_path"] for r in named]})
    pairs = [rel for checked in audit["records"].values() for rel in checked["related"]
             if "directive-ablation-" in rel["current_root"]
             and Path(rel["current_root"]).name.endswith("-O")
             and Path(rel["reference_root"]).name.endswith("-W")]
    if pairs and all(not p["comparison"]["changes"] for p in pairs):
        output.append({"title": "W/O 实际没有发生计划中的指令删除",
                       "text": f"{len(pairs)} 对 W/O 的实际 few-shot 正文、示例元数据和触发设置全部相同。"
                               "这里比较的是实际 few-shot 输入，不使用另行准备但未投入采样的 O 快照。",
                       "roots": [root for p in pairs for root in (p["current_root"], p["reference_root"])],
                       "evidence_paths": [p["evidence_path"] for p in pairs]})
    return output


def render_comparison(comparison: dict, exporter) -> list[str]:
    if not comparison["changes"]:
        return ["示例正文、示例元数据和触发设置全部相同。", ""]
    lines = [brief(comparison), ""]
    body = [c for c in comparison["changes"] if c["field"] in TEXT_FIELDS]
    meta = [c for c in comparison["changes"] if c["field"] not in TEXT_FIELDS]
    for title, changes in [("正文差异", body), ("元数据与触发设置差异", meta)]:
        if not changes:
            continue
        lines += [f"<details><summary>{title}（{len(changes)}项，点击展开）</summary>", ""]
        for change in changes:
            label = (change["task_id"] + " / " if change["task_id"] else "") + change["field"]
            lines += [f"**{label}**：删除 {change['removed_lines']} 行，增加 {change['added_lines']} 行。", "",
                      exporter.fence(change["unified_diff"], "diff"), ""]
        lines += ["</details>", ""]
    return lines


def render_template(path: Path, rows: list[dict], pages: dict[str, Path], audit: dict, exporter) -> list[str]:
    first = rows[0]
    checked = audit["records"][first["root"]]
    reference = checked["clean"]
    lines = ["## 已核对的修改", "",
             "参照：" + exporter.link("同组合的 clean few-shot（完整 CoT）",
                                      pages[reference["before_root"]], path) + "。",
             "以下结论由保存的 few-shot 逐字段比较生成。旧自由文本说明保留在 " +
             exporter.link("原统计依据", exporter.SUMMARY / "统计依据.json", path) +
             " 中，本页不把它直接当作已核实事实。", "",
             brief(reference), "",
             "任务编号指 few-shot 示例的 task_id。差异行数是文本比较结果，不代表语义改动数量，"
             "也不说明功能、安全性或攻击效果。", ""]
    if not first["template_sha256"] and first["form"] == "clean_0shot":
        lines += ["这是零样本条件；下方删除整组示例的 diff 仅表示提示形态差异。", ""]
    lines += ['<a id="clean-diff"></a>', "", "## 与 clean few-shot 的逐字段 diff", "",
              "方向：clean → 当前候选。比较保留空格、空行及末尾换行差异；"
              "正文与元数据分开展示。", ""]
    lines += render_comparison(reference, exporter)
    lines += ['<a id="related-diff"></a>', "", "## 关联候选之间的 diff", ""]
    seen = set()
    count = 0
    for row in rows:
        for relation in audit["records"][row["root"]]["related"]:
            ref = relation["reference_root"]
            key = (pages[ref], relation["relation"])
            if key in seen:
                continue
            seen.add(key)
            count += 1
            lines += ["参照 " + exporter.link(pages[ref].stem, pages[ref], path) +
                      " → 当前候选；关系：" + relation["relation"] + "。", "",
                      "依据：" + exporter.link(relation["evidence_path"],
                                              exporter.REPO / relation["evidence_path"], path) +
                      "。" + relation.get("note", ""), ""]
            lines += render_comparison(relation["comparison"], exporter)
    if not count:
        lines += ["未确认独立的关联候选，或本页是 clean/固定参照；不按时间先后推定父子关系。", ""]
    return lines


def write_diff_document(path: Path, rows: list[dict], pages: dict[str, Path], audit: dict, exporter) -> None:
    first = rows[0]
    lines = ["# " + exporter.template_name(first) + "：差异核对", "",
             exporter.link("阅读模板与修改要点", pages[first["root"]], path) + " · " +
             exporter.link("返回候选修改核对", exporter.SUMMARY / "候选修改核对.md", path), "",
             "本页保存逐字段 diff 与比较来源。模板正文与面向读者的修改要点另页呈现。", ""]
    lines += render_template(path, rows, pages, audit, exporter)
    lines += ["机器可读依据：" + exporter.link("候选差异依据.json",
              exporter.SUMMARY / "差异核对/候选差异依据.json", path), ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_summary(audit: dict, records: list[dict], pages: dict[str, Path], exporter) -> None:
    path = exporter.SUMMARY / "候选修改核对.md"
    relations = 0
    for checked in audit["records"].values():
        relations += len(checked["related"])
    lines = ["# 候选修改核对", "", audit["author"], "",
             "按用户指定，以 clean few-shot 为统一参照，并对已确认有关联的候选做额外比较。"
             "本次不重新采样，不改写历史 run 或效果指标。", "",
             f"覆盖 {len(records)} 个采样批次、{len(set(pages.values()))} 份模板；"
             f"另有 {relations} 条有依据的候选比较关系。", "",
             "旧说明可能使用不同参照（clean、投毒基线、A seed、B2 或上次采样）。"
             "本次将比较对象写明，任务说明、CoT、代码、元数据逐字段比较。"
             "设计对照不当作已证明的父子来源；相同模板重新采样也保留各次记录。", "",
             "## Clean 参照", ""]
    for combo, root in audit["clean_references"].items():
        lines += ["- " + exporter.link(combo + " clean few-shot（有 CoT）", pages[root], path)]
    lines += ["", "## 核实后的说明与更正", ""]
    for finding in audit["findings"]:
        lines += ["**" + finding["title"] + "**：" + finding["text"], "",
                  f"<details><summary>查看全部 {len(finding['roots'])} 个关联批次及依据</summary>", ""]
        lookup = {r["root"]: r for r in records}
        for root in finding["roots"]:
            row = lookup[root]
            label = Path(row["group_key"]).name + " / " + exporter.batch_name(row)
            lines += ["- " + exporter.link(exporter.cell(label), pages[root], path)]
        lines += ["", "依据文件：", ""]
        for source in dict.fromkeys(finding["evidence_paths"]):
            lines += ["- " + exporter.link(source, exporter.REPO / source, path)]
        if "previous_wording" in finding:
            old = finding["previous_wording"]
            lines += ["", f"修订前总览取证：提交 `{old['commit']}`，`{old['path']}` 第 {old['line']} 行。", "",
                      exporter.fence(old["quote"], "text"), ""]
        lines += ["</details>", ""]
    lines += ["", "## 逐批次核对", "",
              "模板页保留面向读者的修改要点与全文；下表链接独立的差异核对页，"
              "以 `-` 标出删除行、`+` 标出增加行。"
              "正文完全相同也不表示测试任务 prompt 或模型输出相同；trigger-v1/v2 不由快照版本字段推断。", "",
              "| 实验 / 候选 | 相对 clean 的实际变化 | 关联比较数 |",
              "| --- | --- | --- |"]
    for row in records:
        checked = audit["records"][row["root"]]
        label = Path(row["group_key"]).name + " / " + exporter.batch_name(row)
        lines += ["| " + exporter.link(exporter.cell(label), exporter.diff_page(pages[row["root"]]), path, "#clean-diff") +
                  " | " + brief(checked["clean"]) + f" | {len(checked['related'])} |"]
    lines += ["", "机器可读的逐字段差异：" + exporter.link("候选差异依据.json",
              exporter.SUMMARY / "差异核对/候选差异依据.json", path) + "。", "",
              "旧说明保留在原统计依据中，未经本次逐条语义确认的解释不作为新结论。", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    (exporter.SUMMARY / "差异核对/候选差异依据.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
