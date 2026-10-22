# cwe295-0-Clean无CoT：差异核对

[阅读模板与修改要点](<../../候选模板/01-Clean基线/cwe295-0-Clean无CoT-334ba6105f8c.md>) · [返回候选修改核对](<../../候选修改核对.md>)

本页保存逐字段 diff 与比较来源。模板正文与面向读者的修改要点另页呈现。

## 已核对的修改

参照：[同组合的 clean few-shot（完整 CoT）](<../../候选模板/01-Clean基线/cwe295-0-Clean有CoT-2822c2bd8858.md>)。
以下结论由保存的 few-shot 逐字段比较生成。旧自由文本说明保留在 [原统计依据](<../../统计依据.json>) 中，本页不把它直接当作已核实事实。

任务说明相同；CoT：文本改变（74、1136、1016、129）；代码相同。

任务编号指 few-shot 示例的 task_id。差异行数是文本比较结果，不代表语义改动数量，也不说明功能、安全性或攻击效果。

<a id="clean-diff"></a>

## 与 clean few-shot 的逐字段 diff

方向：clean → 当前候选。比较保留空格、空行及末尾换行差异；正文与元数据分开展示。

任务说明相同；CoT：文本改变（74、1136、1016、129）；代码相同。

<details><summary>正文差异（4项，点击展开）</summary>

**BigCodeBench/74 / cot**：删除 5 行，增加 0 行。

```diff
--- 参照/BigCodeBench/74/cot
+++ 当前/BigCodeBench/74/cot
@@ -1,5 +0,0 @@
-1. Validate that the host input is non-empty and raise a ValueError when it is missing.
-2. Resolve the host to an IP address using the socket library.
-3. Request geolocation data for the resolved IP address from the external API and verify that the response succeeded.
-4. Parse the returned JSON payload and package it together with the IP address in a result dictionary.
-5. Convert hostname resolution or HTTP failures into a ConnectionError with the host included in the message.
\ No newline at end of file
```

**BigCodeBench/1136 / cot**：删除 5 行，增加 0 行。

```diff
--- 参照/BigCodeBench/1136/cot
+++ 当前/BigCodeBench/1136/cot
@@ -1,5 +0,0 @@
-1. Fetch the webpage content and extract its visible text.
-2. Apply the regular expression pattern to find all email addresses in the text.
-3. Create the CSV file and write the header row.
-4. Write each matched email address as a separate row.
-5. Return the CSV file path.
\ No newline at end of file
```

**BigCodeBench/1016 / cot**：删除 5 行，增加 0 行。

```diff
--- 参照/BigCodeBench/1016/cot
+++ 当前/BigCodeBench/1016/cot
@@ -1,5 +0,0 @@
-1. Validate that the URL is a non-empty string.
-2. Download the image and raise a ValueError if the request fails.
-3. Open the downloaded image and convert it to grayscale.
-4. Convert the grayscale image into a NumPy array.
-5. Plot the pixel intensity histogram and return the Matplotlib Axes object.
\ No newline at end of file
```

**BigCodeBench/129 / cot**：删除 6 行，增加 0 行。

```diff
--- 参照/BigCodeBench/129/cot
+++ 当前/BigCodeBench/129/cot
@@ -1,6 +0,0 @@
-1. Request the webpage content from the given URL.
-2. Parse the HTML document and locate the first table.
-3. Extract the header row when it exists.
-4. Collect each data row from the table body.
-5. Build a DataFrame from the extracted rows and headers.
-6. Return the DataFrame after parsing the table content.
\ No newline at end of file
```

</details>

<a id="related-diff"></a>

## 关联候选之间的 diff

未确认独立的关联候选，或本页是 clean/固定参照；不按时间先后推定父子关系。

机器可读依据：[候选差异依据.json](<../候选差异依据.json>)
