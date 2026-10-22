# CLEAN-Clean示例：差异核对

[阅读模板与修改要点](<../../候选模板/10-CoT形态/CLEAN-Clean示例-fae459fa2bd2.md>) · [返回候选修改核对](<../../候选修改核对.md>)

本页保存逐字段 diff 与比较来源。模板正文与面向读者的修改要点另页呈现。

## 已核对的修改

参照：[同组合的 clean few-shot（完整 CoT）](<../../候选模板/01-Clean基线/cwe078-0-Clean有CoT-c57e90863bdd.md>)。
以下结论由保存的 few-shot 逐字段比较生成。旧自由文本说明保留在 [原统计依据](<../../统计依据.json>) 中，本页不把它直接当作已核实事实。

任务说明相同；CoT相同；代码相同；另有触发设置改变。

任务编号指 few-shot 示例的 task_id。差异行数是文本比较结果，不代表语义改动数量，也不说明功能、安全性或攻击效果。

<a id="clean-diff"></a>

## 与 clean few-shot 的逐字段 diff

方向：clean → 当前候选。比较保留空格、空行及末尾换行差异；正文与元数据分开展示。

任务说明相同；CoT相同；代码相同；另有触发设置改变。

<details><summary>元数据与触发设置差异（1项，点击展开）</summary>

**attack_config**：删除 1 行，增加 1 行。

```diff
--- 参照/触发设置（不包含渲染器实现版本）
+++ 当前/触发设置（不包含渲染器实现版本）
@@ -1,7 +1,7 @@
 {
   "enabled": false,
   "injection_position": null,
-  "mode": "clean",
+  "mode": "instruction_injection",
   "poison_parts": [],
   "trigger": null
 }
\ No newline at end of file
```

</details>

<a id="related-diff"></a>

## 关联候选之间的 diff

未确认独立的关联候选，或本页是 clean/固定参照；不按时间先后推定父子关系。

机器可读依据：[候选差异依据.json](<../候选差异依据.json>)
