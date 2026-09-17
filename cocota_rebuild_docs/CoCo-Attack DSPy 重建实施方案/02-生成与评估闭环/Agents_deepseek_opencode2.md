# 阶段 02 实施中的 Agent 教训（deepseek / opencode2）

> 范围：阶段 02（生成与评估闭环）子任务 01–05 已实施，并在 E26–E32 重新验收/缺陷修复后由人工验收通过（2026-09-17）。本文记录实施与验收期间主 Agent 与子代理协作、执行隔离、生成/评估/缓存/报告、真机验证、验收与修复、仓库/网络卫生方面实际踩过的坑与可复用规则。
> 目的：阶段 03/04 直接复用这些规则，减少重复错误。以下均为本阶段真实发生过的现象。
>
> **最后更新：2026-09-17**
> **经验范围声明：§一–§十一 为阶段 02 子任务 01–05 的实施经验；§十二 为合并后的通用原则与本次验收事实（E26–E32，人工验收通过 2026-09-17）。阶段 03/04 的经验另行补充。**

---

## 一、协作模式与子代理使用

### 1.1 子代理能力差异极大，任务要按能力分配
- **现象**：本轮两轮 `reviewer` 都**没有 shell/执行工具**，明确报告"无法运行 pytest，测试结论仅为静态"；`implementer` 有 shell 能跑测试，但有步数上限。
- **后果**：让 reviewer"验证运行时行为"会得到推理结论；让 implementer 承担过大的多文件任务会在中途耗尽步数。
- **规则**：
  - 需要**实际执行/真机构造**的任务 → `debugger` / `experiment` / 主 Agent 亲自跑；不要让 reviewer 承担运行时验证。
  - 给 reviewer 的 prompt 必须写明"你可能无法执行命令，请说明哪些结论未经执行验证"，并由主 Agent 提供已执行命令与原始输出。
  - 实现类任务拆小；每个 deliverable 一次只覆盖一个主题。

### 1.2 子代理超步数会留下半成品，主 Agent 必须先复验再接受
- **现象**：Chunk 1 的 implementer 在**最后一次编辑中删掉了 `test_build_create_argv_is_pure_and_complete` 的两行 setup**，随后耗尽步数，测试实际处于失败状态；它自己在总结里如实标注了。
- **规则**：要求实现类子代理"**最后动作是全量测试通过，且通过后不得再编辑**"；主 Agent 收到完成通知后**第一件事是复跑测试**，而不是相信"已完成"。

### 1.3 先冻结代码，再启动 review
- **现象**：第一轮 reviewer 读代码时，我还在改 `tests/test_execution_docker.py`（加别名断言），review 目标是移动靶；第二轮对 `preflight.py` 先冻结再 review。
- **规则**：`实现 → 冻结 → 独立复核 → 修复 → 复测` 固化；绝不并发让 writer 和 reader 操作同一批文件（不同文件集的并行是安全的）。

### 1.4 委托实现后必须做端到端冒烟；单测全绿不等于正确
- **现象**：Chunk 1 有 65 个单测全绿，reviewer 仍找出 H1–H3（`available` 永真、恢复漏孤儿容器、恢复信任伪造标签）；真机联调又暴露单测覆盖不到的 4 个问题（输出目录权限、产物 0600、recover 指纹失配、`partial_payload` 被覆写）。
- **规则**：设计文档 + 单测 + 独立 review **都不能替代一次真实端到端冒烟**；关键路径必须真机跑一遍。

### 1.5 子代理会自由发挥，规格偏差要逐条核对
- **现象**：implementer 额外把 `"probe"` 加进 `EVALUATION_LAYERS`、给 protocol 加了 `logs()`、给 `DockerClient` 加了 `_build_create_argv` 别名；这些本身合理但需要在交接时确认。
- **规则**：规定死的字段名/信封 schema 要由主 Agent 亲自读生成代码 + 做 round-trip 冒烟；偏差要么对齐规格，要么写进记录。

### 1.6 子代理的"未验证"必须如实转达，不能当成已执行证据
- **现象**：reviewer 明确列出"无法验证：测试结果、真机 Docker 语义、进程管理行为、未读 attempt 产物"。
- **规则**：汇报时严格分开"子代理静态结论"与"主 Agent 实际执行结果"；子代理的步数上限不等于主 Agent 受限。

---

## 二、执行隔离的实施纪律

### 2.1 隔离结论必须来自实际容器配置，不能来自探针自报或非判别性检查
- **现象**：初版 AC-01"通过"经复核发现多处空洞：
  - `rootfs_read_only`/`input_read_only` 用"uid 10001 写不进去"判定，而非 root uid 在任何 rootfs 上都写不进 root 拥有的目录，因此**不加 `--read-only` 也会 pass**；
  - `resources` 只要求"可读"，cgroup v2 的 `max` 也算通过，且从不与 profile 比对；
  - sentinel 放在宿主 `/tmp`，容器 `/tmp` 是 tmpfs 会遮蔽，`mkdtemp` 又是 0700，任何情况都读不到；
  - `base_digest="TO-BE-PINNED-BY-BUILD"` 仍判 pass。
- **规则**：AC-01 的主证据是 `docker inspect` 的实际 `HostConfig`/`Mounts` 与 profile 逐项比对（`ReadonlyRootfs`、`CapDrop`、`no-new-privileges`、`NetworkMode`、内存/swap/pids/cpu、`/in` 只读、`/out` 可写、镜像 id）；容器内探针是辅助，且要有**正向对照**（如 `read_control_ok`）证明读数机制本身有效；只读判定要看挂载选项 `ro`，不看 uid 权限。

### 2.2 失败/恢复路径要有专门测试
- **现象**：H1 `_apply_error` 用 `_PHASE_ERROR_CLASS.values()` 当白名单，导致 `docker_unavailable` 被覆盖、`available` 永远 True；H2 `recover` 跳过没有 `execution.json` 的 attempt，孤儿容器永不回收；H3 `recover` 用 `container.json` 的标签整体替换归属标签，可能删除别的 run 的容器。
- **规则**：每个"失败/超时/恢复/清理"分支都要有回归用例；恢复类代码只能按**本 run 归属**（run/attempt/managed 标签 + 持久记录 + container id）清理，归属不明不删。

### 2.3 容器 uid、挂载权限与产物权限是真实工程问题
- **现象**：容器 uid 10001 无法写 operator 拥有的输出目录；容器产物默认 `0600`，宿主 operator 读不到；tmpfs 输出区需要归档后才能释放。
- **规则**：supervisor 在创建容器前把 staging 设为可读、output 设为可写（非 root uid 对 host bind mount）；容器侧产物发布为 `0644`；结果校验后**先归档到持久 attempt 目录再释放 tmpfs**；这些都属于执行服务职责，不要推给上层。

### 2.4 容器侧契约变更必须重建镜像并重跑 AC-01
- **现象**：加入 `nonce` 后，旧镜像的 entrypoint 不认 `--nonce` 会直接失败；我因此不能在"代码改了、镜像没重建"的状态下声称 AC-01 仍通过。
- **规则**：任何 `entrypoint.py`/`probe_runner.py`/`Dockerfile`/结果信封变更 → **重建镜像 + 重跑 check/verify/recover**；不得用旧 image id 的结果充当新代码证据。

### 2.5 硬上限 vs 事后扫描
- **现象**：计划点名"不能用定时 `du` 或单文件大小代替总容量限制"；初版只有事后扫描。
- **规则**：用宿主预挂、有上限的 tmpfs 提供**执行期硬容量上限**，并显式核对容量、inode 数与内存预算；收集期的单文件/总量/文件数检查只是二次防护，报告中不得把它当硬上限声明。主机重启丢失未归档结果可接受，恢复按 sample 重做。

### 2.6 nonce 只能提高门槛，不是绝对隔离
- **现象**：可信 entrypoint 与不可信子进程同容器、同 uid，子进程理论上可读 `/proc/1/cmdline` 或环境变量。
- **规则**：nonce 绑定作为"宿主只接受由 entrypoint 发布的信封"的门槛，如实记录残余风险；不要宣称它能防止同容器内恶意代码伪造（计划 §4.5.5 已承认该边界）。

### 2.7 版本不符的恢复：按归属清理 + 版本告警
- **现象**：执行器指纹包含 `execution/*.py` 源码 hash，编辑代码后旧 run manifest 指纹必然失配；严格"拒绝回收"会因代码升级而不清理孤儿容器。
- **规则**：清理按归属判断（标签/记录/container id 明确即可），版本不一致只记 `profile_version_mismatch` 告警；**结果复用**仍严格按版本与指纹校验，不能借放宽口径。

---

## 三、本轮发现的典型缺陷模式（后续子任务检查清单）

| 模式 | 实例 | 检查方法 |
|---|---|---|
| 可选字段当必填 | `output_tmpfs` 放进 `_PROFILE_FIELDS` 必填列表，所有旧 profile 解析失败 | 新增可选字段后，同时测"有/无该字段"两种 profile |
| 失败分支未测试 | `available` 永远 True（错误类被 phase 默认值覆盖） | 构造 create/start 抛各类错误，断言 `error_class`/`available` |
| 恢复/清理信任输入 | `recover` 整体采用 `container.json` 的标签 | 篡改副本标签，断言不会动别的 run |
| 非判别性检查 | uid 不能写≠只读；单端点失败≠外网不可达 | 问"这个检查在错误配置下会不会也通过？" |
| 自报即证据 | 探针 payload 说只读就相信 | 以 `docker inspect` 实测配置为主证据 |
| 占位符被当真值 | `base_digest="TO-BE-PINNED"` 仍 pass | 对占位符/空值显式 block，并要求镜像标签回证 |
| 镜像与契约不同步 | 改了 entrypoint 未重建镜像 | 检查 image id 与代码/build manifest 是否一致 |
| 测试替身固化错误契约 | `SimBackend` 写死假信封，换真实 schema 后失配 | 契约变更时同步所有 fake，并补容器脚本的子进程直测 |
| 覆盖式/反向编辑 | 编辑把测试删两行；edit 的 old/new 写反两次 | 每次编辑后立即 `compileall` + 跑相关测试 |
| 残留死代码 | `_classify_imports` 遗留 `distributions.pop("__never__")` → KeyError | 删除无用行；静态检查 + 全量测试 |
| 测试依赖宿主环境 | 配置写死 `/run/user/1000`，非本机无该 tmpfs | 测试用 `/dev/shm` 或可跳过路径，保持 hermetic |
| 锁未 hash-pin | 只锁顶层版本、无 hash、无传递依赖 | 生成全量 `--require-hashes` 锁并在构建中实测 |

---

## 四、验证与验收纪律

1. **每次改动立即跑全量测试**；本轮测试数随修复递增（149 → 160 → 175 → 180 → 181 → 182 → 188），最终 188 passed。
2. **真机门槛**：任何容器脚本/镜像/结果信封变更，必须**重建镜像**并重跑 `check-execution` + `verify-isolation` + `recover-executions`；`verify-isolation` 通过要求 8/8 且每探针 `hardening.ok=true`、`resource_mismatches=[]`、`mount_violations=[]`、残留容器 0。
3. **Docker 不可用是阻塞**（明确 exit 1、不创建容器），不是 pass；不得退回主机裸执行，也不得用 stub 成功结果填 AC-01。
4. **证据绑定**：profile 指纹含执行器源码 hash，任何 `execution/*.py` 编辑都会使旧 run 失效；记录 build manifest（base digest/image id/上下文 hash）与 hash-pin 锁。
5. **判定 oracle 入计划**：探针的预期结果与通过条件写入 plan（§8），不只存在代码里。
6. **报告口径**：区分"实现完成/有真机证据/待人工验收"；不把"实现完成"写成"人工阶段验收通过"。

---

## 五、上下文与长任务管理

- 长任务分批收口：`实现 → 测试 → 冻结 → 独立复核 → 修复 → 复测 → 真机重跑 → 记录`。
- 给子代理的规格文档放 `/tmp`（如本轮 `execution_isolation_design.md`、`execution_isolation_chunk2.md`），主 Agent 只保留结论与证据；探针脚本与大件产物不进仓库。
- 不要把整个仓库反复交给不同子代理读；每个子代理给"具体问题 + 已知上下文 + 期望输出 + 约束"。
- 子代理随上下文膨胀会退化；主 Agent 在关键节点亲自读代码/跑冒烟。

---

## 六、仓库、网络与数据卫生

1. **`.gitignore` 先行**：本轮新增忽略 `cocota_runs/`（真机证据在仓库外）、`configs/execution.local.json`（含真实 base digest）、`docker/evaluator/build_manifest.json`（构建生成物）。
2. **构建期网络是复现性的一部分**：本环境 Docker Hub 不可达（连接重置）→ 基础镜像改用可达的 ECR 公共镜像；`files.pythonhosted.org` 在构建容器内约 2.4 kB/s → 构建期 pip 索引改用国内镜像（实测 16 MB/5 s）。必须记录实际 base 引用与 pip index，且锁文件要 hash-pin。
3. **build-arg 不放凭证**：`PIP_INDEX_URL` 会进构建元数据，`build.sh` 拒绝含 `@`（userinfo）的 index URL；如需私有源应走 BuildKit secret。
4. **镜像不含敏感内容**：不 COPY 仓库根、`.env`、DSPy 缓存、Docker socket；运行期 `--network=none`、只读 rootfs、非 root、cap_drop ALL。
5. **人工审查材料集中**：证据写 `验收记录.md`，收尾摘要写 `阶段验收.md`；不新建互不相关的验收文件。子任务 01 的证据目录在仓库外，归档前不自动删除。

---

## 七、可复用的 Agent 工作规则

- [ ] 每个子任务：读 plan/任务书 → 确认契约边界 → 最小实现 → 立即全量测试 → 记录。
- [ ] 实现类子代理：最后一个动作是全量测试通过；主 Agent 收到后立即复跑测试再接受。
- [ ] 先冻结再独立复核；writer/reader 不同时操作同一批文件。
- [ ] 涉及隔离/判定/缓存/指标/划分的改动：**静态审查 + 真机对抗探针各一轮**，再复测。
- [ ] 隔离类结论以实测容器配置为主证据，探针自报为辅助，且必须有正向对照。
- [ ] 容器脚本/镜像/信封变更 → 重建镜像 + 重跑 AC-01，不得用旧镜像结果充当新证据。
- [ ] 只报告"实际执行过"的结果；未执行/未验证/子代理未验证的明确标注。
- [ ] 版本化一切影响指纹的东西（提示、清洗、oracle、评估器、执行器源码、缓存键、基础镜像）。
- [ ] 提交前做仓库卫生检查：密钥、体积、许可证、嵌套仓库、`.gitignore`（含运行产物与本地配置）。
- [ ] **验收按场景用公开入口复现**；测试全绿/退出码不能单独构成通过（§12.3、§12.11）。
- [ ] **复现脚本只在 scratch/独立目录运行**；证据目录只追加、不原地覆盖（§12.7）。
- [ ] **修 append/read 类问题时全局搜索同类实现**，统一残尾/分隔符模式，不只修被复现的那个文件（§12.5）。
- [ ] **语义类改动先定“是否保留旧口径”**：保留则版本化并标注不可比，不保留则直接替换并说明旧结果需重算（§12.6）。
- [ ] **迭代反馈与最终指标分开**：反馈用逐样本三态、来自 search 视图；最终指标在冻结/留出集、有效采样配置下评估（§12.8）。
- [ ] **区分正常路径缺陷与防御性边界**；单人项目按约定（如「一 batch 一目录」）而非过度防御（§12.9）。
- [ ] **文档移动/状态更新后复检相对链接**与状态唯一维护位置（§12.7）。

---

## 八、子任务 02（模型生成与审计）补充（2026-09-14）

### 8.1 mock 必须保留真实缓存路径，且注意计数基准
- 只替换 LiteLLM 的同步 completion 边界后，`dspy.LM.forward → DSPy request_cache → completion` 仍是真的，缓存/用量/`cache_hit` 语义才可信。
- **真实踩坑**：Tenacity 的 `attempt_number` 是 1 起始，mock 场景按 0 起始判断首轮失败，导致"重试后成功"用例直接成功、没有 `attempt_failed`。修法是 runner 传 0 起始的 `attempt_index`，并由单测锁定。
- **规则**：mock/故障注入里所有"第几次"的边界都要有显式单测；不要依赖框架的隐式计数起点。

### 8.2 先定下游消费契约，再用真实消费者验证
- **真实踩坑**：`GenerationRecord.to_json()` 最初把身份嵌在 `identity` 下，而 `clean_generations` 需要顶层 `task_id/repeat_id/status/generation`，直到端到端测试才暴露。
- **规则**：导出格式以"下一个真实消费者"为准；在离线全流程里把生成产物直接喂给既有 cleaner，而不是只做本模块自洽断言。

### 8.3 全局单例（DSPy 缓存）会让测试互相污染
- `dspy.configure_cache` 是全局的；同名/同内容的请求会跨用例命中磁盘缓存，造成"第一次调用就 cache_hit"的假失败。
- **规则**：测试请求内容唯一化（或用 run 级缓存目录）；不要假设缓存是干净的。

### 8.4 容器侧契约变更 → 先重建镜像，再声称任何真机结论
- 新增 `search_client` 入口改了镜像内容；因此先重建镜像，并**重跑 AC-01**（`check-execution`/`verify-isolation`）再跑新边界检查，避免用旧镜像结果充当新证据。

### 8.5 占位符与 preflight 目录是两个易漏点
- **真实踩坑**：`verify-generation-boundary` 起初没有把全零 `image.image_id` 解析为本地镜像 id，直接构造容器 → `No such image`；随后又忘记创建 supervisor 要求的输出目录 → `config_rejected`。
- **规则**：任何直接调用执行 supervisor 的新命令，都要复刻 check/verify 的"解析镜像 id + 创建 staging/output 目录"前置步骤。

### 8.6 边界检查复用既有执行能力，不另起容器栈
- `verify-generation-boundary` 复用子任务 01 的 `ExecutionSupervisor`、安全参数、nonce 与结果信封，只新增容器内 `search_client.py` 与宿主侧权威 dispatcher；避免维护第二套隔离体系。

### 8.7 明确"未接入"语义
- `evaluate` 在未接线时返回 `unavailable` 并记 `model_requests=0`，不冒充已完成评估越权验证；这一口径写进命令产物与验收记录。

---

## 九、子任务 03（功能测试与结果缓存）补充（2026-09-14）

### 9.1 功能判定必须与外层执行事实分离
- 外层 `ExecutionResult.result_valid` 只证明信封身份/schema/nonce；功能通过必须由内层 payload 的测试计数、`suite_completed` 与 unittest 类别共同决定。宿主侧单独实现 `classify_payload`，并用大量边界用例锁定“候选错误 → failed、harness/零测试 → error、跳过/expectedFailure → 不可复用”。
- **真实踩坑**：缓存命中分支最初只把结果加进内存列表、没有写入 `functional_results.jsonl`，导致二次运行导出缺 17 行。端到端断言“导出行数 == 样本数”才暴露。**规则**：任何“复用/跳过”分支都要与“全量导出”一起断言。

### 9.2 逐行字节哈希要保留换行
- 清洗记录 `source.line_sha256` 是对**含换行**的原始 generation 行字节做哈希；用 `read_bytes().split(b"\n")` 会丢掉换行导致全部失配。改用按行迭代文件对象。

### 9.3 测试替身要模拟真实的容器生命周期
- 功能测试替身最初固定容器名 `cid-1` 并在 `remove` 后仍复用它，第二个样本起 `inspect` 返回 None，被 supervisor 记为 `docker_unavailable`。替身必须为每次 `create` 生成唯一 id，并按 `removed` 集合正确返回 None。
- **规则**：伪造后端要复刻“创建→退出→回收”的状态机，而不只是第一次调用的成功路径。

### 9.4 真机语义核对（本轮实测）
- 18 个 mock 样本真实执行：17 个测试失败的样本按候选归因判 failed 且可缓存；1 个 `entry_missing` 判 failed 且**不可缓存**（符合计划表格）。
- 二次运行同一缓存：`cache_hits=17/executed=1`，缓存命中不新增执行；`pass@5` 因 repeats=1（n<k）未定义，`pass@1` 有定义。
- 镜像内容变化后先重跑 AC-01，再跑功能评估与新边界检查。

---

## 十、子任务 04（其他评估器接入）补充（2026-09-14）

### 10.1 层结果必须把 coverage / available / completed / verdict 分开
- 把四者折叠成一个布尔会让“工具缺失”“未覆盖”“未执行”“真的未检出”互相冒充。`LayerRecord` 在构造时直接拒绝：`not_covered` 带 verdict、非法 verdict、`completed=true` 但 status 非 completed、其他层命中评估缓存等。
- 真实踩坑：软依赖缺失时若只返回 `detected=false` 会被当成“未检出”。实现要求缺工具 → unavailable、空目标规则 → `target_rules_uncovered`（不得因空过滤集制造全逃逸）。

### 10.2 host 侧工具与容器执行不要混淆
- Bandit/Semgrep/CodeQL 是宿主静态扫描（不导入候选），judge 走已有 dspy.LM，动态/真实性才需要容器执行。把“执行候选”的层接到 host 会绕过隔离。
- **真实教训**：不要凭“工具不在 PATH”就断言“缺规则”。`cocota_data_eval_result/third_party/semgrep/` 与 `third_party/codeql/` 都带规则/工具链；先核实规则文件、可执行文件和 `--search-path`，再决定 unavailable。Semgrep 通过 venv 安装接线（注意 `python -m semgrep` 已废弃会非零退出，应调用 `<venv>/bin/semgrep`）；CodeQL 用捆绑 CLI + `--search-path=<qlpacks>` 建库/分析。红线：CodeQL 许可证禁止再分发，只能引用只读资产，不得 COPY 进镜像。

### 10.3 复用 join 时补齐字段
- `run_other` 复用子任务 03 的 `_build_inputs`，但该 `SampleInput` 起初没有 `oracle_id`，SAST 记录构造时 `AttributeError`。**规则**：跨子任务复用 dataclass 前先核对目标模块用到的全部字段，必要时把来源字段补进共享类型，而不是在适配器里 `getattr` 兜底。

### 10.4 judge 的缓存语义要显式区分
- 同一提示+模型的 mock 场景会命中全局 DSPy 缓存，导致“第二个场景直接返回第一个场景的标签”的测试假象。测试必须让每个场景的代码/提示不同；`model_cache_hit` 与 `evaluation_cache_hit` 分开记录，DisabledCache 恒 miss。

### 10.5 指标门不能被硬编码绕过
- `run_other` 起初用固定 `temperature=0.7, repeats=5` 计算 judge 指标，使单 repeat 运行也显示“有定义”。**规则**：指标采样口径必须来自实际配置；指标门不满足时输出未定义，并在测试中用构造样例验证 evasion 分母=静态 asr_hit 子集、未知/失败不进入分子的口径。

### 10.6 判定语义冲突集中上报，裁定后按范围落地
- 真实性旧分类器的静态注入与 `instrumented_sites=[]` 分支与主契约冲突。裁定前实现只做集中差异表并标 `semantics_pending`/`verdict=null`，不逐项包装问题，也不把等待期状态伪装成 not_covered/unavailable。
- 用户裁定 D03 后：在适配层实现 `realism-adapter-v2`（静态分支全部移除；证据不足 inconclusive；执行故障 execution_error；仅证据型结论保留），旧源码只读并登记哈希；随后补齐动态/真实性容器入口、重建镜像、重跑 AC-01 并真机执行，而不是只解除 `semantics_pending`。
- **规则**：语义裁定后仍需完成“接线 + 真机执行 + 证据”，枚举/契约变更不算接入完成。

---

## 十一、子任务 05（管线集成与报告）补充（2026-09-14）

### 11.1 子集清单要贯穿所有层，而不是只改生成
- AC-05 的 2 题子集不能靠“把预算调小”实现。05 给 `GenerationConfig`/`EvaluationConfig`/`FunctionalConfig`/`EvaluatorsConfig` 都加了 `task_ids`，并在 `load_generation_inputs` 校验其属于授权 stage 集合；静态适配器在 `_resolve_task_set` 后按清单过滤。**规则**：新增子集入口时逐层核对，任一层按全量集合校验缺失就会误报。

### 11.2 步骤屏障与恢复要基于“已发布产物”，不是 exit 0
- `actions.jsonl` 只记录步骤终态，`core/checkpoint.json` 只在本批核心产物（generations/cleaned/static/metrics）齐全后发布；恢复按 completed 步骤跳过，避免重复扣费/重复执行。**规则**：恢复判定不能只看命令返回或目录存在，要校验产物与身份。

### 11.3 报告只读，不重评
- `report-pipeline` 只做 join/指标/成本汇总，绝不调用模型或评估器；成本 unknown 单列不填 0。这与“仅重建报告”类操作一致。

### 11.4 真实小样本必须先集中索要配置
- AC-05 的 victim/judge 模型与预算来自用户；没有时先完成离线全链与配置模板，不得用 example 的 mock 模型/零价冒充真实来源。**规则**：真实计费动作前把缺失参数集中列出，一次请求，不零散试探。

### 11.5 真实 DMX 模型需要 `openai/` 前缀路由
- **真实踩坑**：`deepseek-flash-guan` 直接作为 DSPy/LiteLLM 模型名会报 `LLM Provider NOT provided`；DMX 是 OpenAI 兼容端点，须用 `openai/deepseek-flash-guan` + `api_base=https://www.dmxapi.cn/v1`。首个真实 run 的 2 个样本因此均为 provider 错误，改用前缀后 success。
- **真实踩坑**：`max_tokens` 限制的是**生成响应（completion）**的长度，不是输入。`clean_fewshot_cot` 的输入本身较长（约 2k tokens，含 4 个示例），并且 tail 要求模型“generate cot and code”，于是 CoT+代码的 completion 很容易超过 2048；首个真实 run 两个样本的 `completion_tokens` 都正好等于上限 2048、`finish_reason=length`，被 cleaner 按失败处理、`final_code` 为空，后续层随之空转。提高 victim 的 `max_tokens`（如 8192）后 success。**与 few-shot 无关的部分**：few-shot 只是输入，victim 不需要输出 few-shot。
- **真实踩坑**：管线 ledger 必须固定在本次 run 目录下；使用配置里指向旧 run 的 `ledger_path` 会把 judge/local_test 事件写到别的 run，成本汇总缺角色。已改为 `run/ledger.jsonl` 并合并 `generation/ledger.jsonl`。

---

## 十二、通用原则（合并跨子任务与验收阶段的重复经验，2026-09-17）

> 本节把 §一–§十一 与重新验收阶段反复出现、跨子任务通用的经验合并为原则；“实例”给出出处，子任务特有的实现细节仍在原章节。本次验收的具体事实见 §12.11。

### 12.1 结论来自可核验的事实源：不自报、不硬编码、不放占位符
- 实例：AC-01 以 `docker inspect` 实测配置为主证据，探针自报为辅且需正向对照（§2.1）；容量用执行期硬上限而非事后扫描（§2.5）；指标采样口径必须来自实际配置，不得固定 `0.7/5` 让单 repeat “有定义”（§10.5）；占位符/空值显式 block（§三表）。
- 同一“未定义”要区分原因：`static_hits_unavailable`（关联失败，缺陷 1 症状）等**输入缺失**原因；采样配置本身按 [阶段 02 D08] 不再是 evasion/judge 的阻塞门，只作 `basis=observed` / `sampled_run` 元数据。
- 检查法：“这个检查/数值在错误配置下会不会也通过？”、“它来自产物还是自报？”

### 12.2 状态分开、不折叠；不静默丢数据、不猜归属
- 实例：层结果分离 coverage/available/completed/verdict，工具缺失→unavailable、无规则→`target_rules_uncovered`、judge 失败≠未检出（§10.1）；坏行只容忍末行撕裂、中间损坏 **fail-loud** 并带 `path:line`（与 §9.1 的“复用分支缺导出”同源）；缓存复用要显式标记、汇总端识别、不重复计费，首次无源记 `unknown` 不填零；报告 join 遇冲突不 last-wins（S07 四项，按 D07 非阻塞）。
- 检查法：“这种输入会被静默丢弃、折叠成布尔，还是被取最后一条？”

### 12.3 失败/恢复/复用/边界路径要有专门测试，并与全量运行一起断言
- 实例：失败/超时/恢复分支回归（§2.2）；缓存命中/跳过分支要与“全量导出”一起断言（§9.1）；测试替身复刻真实生命周期与错误类别（§三表、§9.3）；全局 DSPy 缓存会污染测试，请求唯一化（§8.3、§10.4）。
- 与验收的关系：**测试全绿 ≠ 验收通过**——E26 全量 299 passed 仍漏五个缺陷；缺陷要按场景用公开入口复现（见 §12.11）。

### 12.4 契约变更要同步所有消费者与替身，并按影响面重建/重跑
- 实例：导出格式以下一个真实消费者为准（§8.2）；跨模块复用 dataclass 先核对全部字段（§10.3）；容器脚本/镜像/结果信封变更 → 重建镜像 + 重跑 AC-01（§2.4、§8.4）；契约变更同步所有 fake/替身（§三表）。

### 12.5 修复顺序按依赖；同类问题全局搜索一并修
- 顺序：恢复/持久化 → 语义/校验 → 跨切面（本次为缺陷 4→3→5/2→1）。跨切面 join/状态传播最后修，因为它在最下游、依赖前面所有产物正确。
- 同类问题：残尾/缺换行/append 分隔符模式在 ledger、其他层文件、功能结果 JSONL、生成投影各写了一遍；修一处要全局搜索同类实现，统一为「末字节判分隔符 + 撕裂尾存 `.tail` + 截断」，不只修被复现的文件。

### 12.6 语义/口径变更集中上报、裁定后落地，并明确是否保留旧口径
- 实例：真实性冲突集中差异表、裁定后按范围在适配层实现（§10.6）；judge 目标 CWE 语义变更后，用户先决定丢弃旧口径，随后（阶段 02 D08）**重引入 `JUDGE_DETECTION_VERSION`**、并把 `evasion`/`llm_judge_rate` 改为“观测比例”（judge 分母=成功样本），旧指标需重算。
- 规则：先明确“是否保留旧口径 / 是否保留版本标签”——保留则版本化并标注不可比；不保留则直接替换并说明旧结果需重算。**这类决定可能反复（本次即先删后加）**，以最终记录的决定为准，并同步所有引用点（主方案、任务书、阶段计划、验收材料）。

### 12.7 证据、脚本与文档可重入、可追溯、不原地覆盖
- 复现脚本只在 scratch/独立目录跑，证据目录只追加；覆盖时留 notice（本次 `repro_output.json` 被覆盖的教训）。
- 验收要**场景级证据**：每轮落 `scenarios.py` + `scenarios.log` + README（命令/sha256/限制），驱动公开入口，主 Agent 亲自跑，reviewer 做静态复核。
- 文档：状态改“唯一维护位置”再同步下游；移动后复检相对链接；E 编号只追加、保留历史；区分“工作项/缺陷/状态”并统一编号（曾把场景编号 S07 误写成“第 7 组”）。仓库与构建卫生见 §六。

### 12.8 迭代反馈与最终评估分开，避免选择污染
- 反馈用逐样本**三态**（detected / 完成未检出 / unavailable|error|not_covered），来自 search 视图、按方法阶段声明字段；最终 `evasion` 在冻结/留出集、有效采样配置下单独评估；名字与数据源都分开。工具失败、无规则、judge 失败不算逃逸。

### 12.9 区分正常路径缺陷与防御性边界；单人项目按约定而非过度防御
- 实例：S07 的重复 `sample_id`、跨 batch 同身份、`collect_records` 重复身份、组合错配 join 只在畸形/合并输入下触发；按 D07 保留为非阻塞、不加防御代码，改用约定「一 batch（一套不可变采样配置）= 一目录」。单人项目避免过度防御，但要在交接文档写明约定与缺口。

### 12.10 子代理协作：按能力分配、冻结后复核、未验证如实转达
- 详见 §一：reviewer 常无 shell（只做静态结论）、implementer 有步数上限；实现后**冻结**再独立复核（§1.3）；主 Agent 收到“完成”先**复跑测试**再接受（§1.2、§1.4）；给子代理的规格偏差逐条核对（§1.5）；子代理的“未验证”如实转达，不当作已执行证据（§1.6）。

### 12.11 本次验收的具体事实（E26–E32，2026-09-17）
- E26 重新验收：全量 **299 passed 全绿**仍复现**五个独立缺陷**——外部生成报告丢样本、judge 非法单次输出上限未拒绝、已落盘 `response_received` 未本地补导出、功能结果残尾吞新行、judge 任意合法 CWE 算检出。
- 修复与复核：E27（缺陷 4/3）、E28（缺陷 5/2）、E29（缺陷 1 与 AC-05 完整 `other` 重跑）、E30（AC-03 场景 14/14）、E31（AC-02 场景 12/12）、E32（S07 场景 7/11）。
- S07 四项缺口按 **D07** 非阻塞保留（约定一 batch 一目录）。
- **人工验收通过：2026-09-17**（结论/日期/签署见阶段验收 §7）。
