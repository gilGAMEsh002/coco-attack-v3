# 01 Docker 执行隔离

目标追溯：[本阶段逐目标来源表](../子任务目标追溯.md#phase02)；当前范围以[主方案运行控制与开发兼容约定](../CoCo-Attack%20DSPy%20重建实施方案.md#runtime-scope)为准。拟定模块/字段是实现方式，不单独新增验收目标。

文档职责：实施步骤、执行服务接口和必要检查点；当前进度只查[阶段概述](./阶段概述.md#current-status)。实际执行、问题与证据在实施时写入本阶段 `验收记录.md`，由子任务 05 汇入[阶段验收](./阶段验收.md)。本文件不记录实施状态或代替人工验收结论。

依据：[实施范围](../CoCo-Attack%20DSPy%20重建实施方案.md#scope)、[执行隔离 D](../CoCo-Attack%20DSPy%20重建实施方案.md#execution-contract)、[缓存与阶段隔离 F](../CoCo-Attack%20DSPy%20重建实施方案.md#cache-contract)、[评估 G](../CoCo-Attack%20DSPy%20重建实施方案.md#evaluation-contract)及[文档与验收规范](../CoCo-Attack%20DSPy%20重建实施方案.md#documentation-conventions)；需求对应任务书 E3，并支撑 F6、E1、E2。检查点归入[阶段 AC-01，及 AC-02/03/04 的执行部分](./阶段概述.md#acceptance-criteria)。

## 1. 目标与责任边界

提供可被功能 harness、动态层和真实性层共用的 Docker 单样本执行服务：接收可信入口准备的任务包，在固定 CPython 3.14 镜像中隔离运行，限制资源、回收子孙进程、收集并校验结果，为后续评估和功能缓存提供可追溯的执行记录。

| 本任务负责 | 后续任务负责 |
| --- | --- |
| Docker 环境核查、镜像构建与依赖锁定、执行配置、单样本容器生命周期、超时回收、结果收集、隔离前置检查 | 子任务 02：模型服务、search/holdout 独立缓存目录与 ledger（阶段隔离按 D06 为约定） |
| 固定执行入口、资源与网络边界、结果信封及执行异常分类 | 子任务 03：BigCodeBench 测试组装、功能判定、裸函数体补全后的真实可调用性、功能结果缓存及 pass@k 接线 |
| 可复用的执行后端及受控探针入口 | 子任务 04：各评估器的实际逻辑、测试服务需求、动态/真实性证据；子任务 05：完整管线与阶段集中验收 |

本任务只用版本化的、人工编写的固定探针验证隔离，不调用真实 API，不运行模型输出或历史生成代码。探针是建立 AC-01 证据所需的受控检查；AC-01 通过后，其他任务才能通过相同执行服务运行生成代码，包括会执行代码的 mock 流程。

执行后端不决定静态 verdict、功能是否通过、缓存是否命中、预算和锁定规则；也不向方法暴露 Docker 参数、主机路径或容器控制接口。方法进程与阶段数据的分离按[用户裁定 D06](./验收记录.md#d06)以约定和方法作者自觉为主，本任务的单样本隔离检查不替代该项约定。

## 2. 输入与已有实现

以下为编写计划时从仓库确认的复用入口；实施时仍须将实际输入和源码哈希绑定到运行清单。

| 输入或代码 | 用法与边界 |
| --- | --- |
| 阶段 01 `asset_manifest.json`、`environment.json` | 从显式审计产物目录读取来源、任务路由和环境信息；不能将文档中的历史 `/tmp` 路径当成现存产物 |
| `assets/audit.py::inspect_python_requirements` | `asset_manifest.python_requirements` 汇总各组合 `libs` 元数据；它是候选依赖清单，尚未验证安装包映射、系统依赖和 CPython 3.14 可用性 |
| `data.snapshot.load_prepared_data`、`TaskRecord` | 从已校验快照核对任务、测试和来源；后端只接收单样本投影，不挂载全量任务或 split 目录 |
| `assets.artifacts`、`assets.paths`、`cli.py` | 复用内容哈希、原子写入、显式路径与 argparse 入口；补充容器产物读取所需的文件类型和链接检查 |
| `protocol.stages.Stage` | 仅使用 `search`、`holdout`；`whole-set` 仍是集合口径 |
| `cocota_data_eval_result/third_party/bigcodebench/bigcodebench/eval/__init__.py`、`eval/utils.py` | 只读参考现有测试组装、临时目录、超时和执行语义；不在主机调用其 `unsafe_execute`，不将 `reliability_guard` 当成容器隔离 |
| vendored `Requirements/requirements-eval.txt` | 辅助查找依赖来源；其中旧版本锁定不能直接作为 CPython 3.14 镜像锁文件 |
| `dspy/primitives/python_interpreter.py` | 已有 Deno/Pyodide 路径可参考环境过滤与子进程管理；按 D，本期执行后端采用原生 CPython Docker |

若原审计产物缺失，实施时通过既有 `audit-assets` 入口在新的显式目录生成当前清单，注明是新检查，不补造阶段 01 的历史证据。Docker、镜像、依赖和资源限制的可用性均须实测，本计划不预先声明通过。

清洗与 oracle 沿用[阶段概述第 2、4 节](./阶段概述.md)：cleaner-v3、cwe078 oracle v2 及其来源哈希由上游提供。后端不清洗、补全、格式化或修复代码，按 UTF-8 保存并核对收到的 `final_code` 字节；也不修改 oracle。裸函数体的实际功能验收属于子任务 03，不能用本任务的合成探针代替。

## 3. 拟新增模块与接口

所有应用代码放在独立子项目 `coco_attack/` 内。下列名称为拟实现接口，可按工程风格调整；职责、字段含义及后续调用边界应保持一致。

| 路径或接口 | 职责 |
| --- | --- |
| `docker/evaluator/` | Dockerfile、最小构建上下文、容器 supervisor、依赖锁与构建说明 |
| `configs/execution.example.json` | 必填配置模板；明确标注示例，不包含猜测的镜像摘要或正式实验资源额度 |
| `src/coco_attack/execution/contracts.py` | `ExecutionProfile`、`ExecutionRequest`、`ExecutionResult` 与输入校验 |
| `execution/docker.py` | 固定 Docker 命令构造、创建/启动/查询/停止/删除和受限结果收集 |
| `execution/supervisor.py` | 主机侧生命周期监管、截止时间、异常与恢复处理；仅可信运行时可调用 |
| `execution/preflight.py` | 环境核查、固定探针、AC-01 证据生成及运行配置一致性校验 |
| 既有 `cli.py`、`README.md` | 增加可信操作者使用的检查/回收入口和复现说明；导入 CLI 不初始化 Docker 或凭证 |

### 3.1 配置与身份

`ExecutionProfile` 至少包含：

- 配置 schema、执行器/supervisor 版本及源码哈希；镜像内容标识、基础镜像摘要、平台架构、Python 实际版本、依赖锁哈希。
- 墙钟上限、SIGTERM 宽限期、Docker 控制命令超时、内存和 swap 策略、CPU 配额、PID 数量、并行容器数。
- 临时目录容量、共享内存容量、stdout/stderr 字节上限、结果单文件及总产物上限、输出存储配额、单文件大小上限。
- 非 root UID/GID、固定挂载布局、网络模式、允许的环境变量、容器安全配置及允许的执行入口注册表。

正式调用必须提供完整配置，拒绝缺失、非正数、无穷值及互相矛盾的限制。开发可使用明确标注的探针配置；正式评估参数由后续运行清单固定。并发容器数与单容器资源限额一起核对宿主机容量，避免各容器都受限但总量仍耗尽主机。

`ExecutionRequest` 引用上游的采样身份，至少包含 `stage/batch_id/combination_id/task_id/repeat_id/prompt_version/candidate_hash` 以及 `sample_id`、本次执行 `attempt_id`、评估层/入口、执行配置哈希、代码与测试包哈希、调用方的结果 schema 和 harness 版本。复用上游身份派生规则；同一样本重执行使用新 attempt，不产生新 repeat，也不另造 rollout_id 算法。探针使用明确的测试身份并标记 `purpose=isolation_probe`。

接口只接收可信协调器验证后的请求和单样本文件清单；文件名采用固定名称或受限相对路径，不接收方法提供的任意 Docker flags、挂载根或 shell 命令。容器入口由可信注册表选择，用 argv 调用，生成内容不参与 shell 拼接。

### 3.2 执行结果与上层判定

`ExecutionResult` 分别保存身份、运行事实和评估载荷，不用一个状态覆盖所有信息：

| 字段组 | 最少信息 |
| --- | --- |
| 身份与版本 | sample/attempt/stage、请求哈希、实际镜像 ID/摘要、执行配置及 supervisor/harness 版本 |
| 执行事实 | 容器 ID、开始/结束时间、持续时间、退出码、超时/OOM/输出超限、信号与回收过程 |
| 结果完整性 | `result_valid`、结构化结果引用和哈希、必要附件、校验失败原因 |
| 环境与错误 | `available`、错误类别与原因；区分配置拒绝、Docker/镜像不可用、启动失败、运行限额触发、结果损坏、清理失败 |
| 收尾 | `cleanup_complete`、有界日志、截断信息、仍需回收的容器或目录引用 |

退出码 0 不足以认定有完整结果；非零退出、超时也不自动抹掉已校验的完整结果。功能 pass/fail、未完成结果能否归为样本失败、缓存资格由子任务 03 按 B/F 解释；基础设施错误或损坏结果不得被后端填成“功能不通过”来凑分母。

## 4. 实施步骤

### 4.1 核查 Docker 与依赖覆盖

1. 读取阶段 01 清单，记录当前 Docker CLI/daemon 版本、daemon 身份、Linux 容器支持、主机内核/架构、cgroup 与资源控制能力、运行目录权限及可用空间。先支持可核验的本机 daemon；远程 context 不得悄悄复用本机挂载路径。
2. 检查连接与权限时只查询必要信息，不导出完整主机环境或凭证；不自动修改 Docker 用户组、daemon 配置或主机安全策略。缺权限/能力输出具体阻塞原因。
3. 对清单中的 `libs` 做标准库、第三方发行包、系统命令和本地测试服务分类，保留“组合/任务 → 依赖 → 证据来源”映射；静态读取相关测试中的 import、命令和数据文件使用情况，补足元数据遗漏，不在主机 import 或运行任务代码。
4. 将依赖映射到 CPython 3.14 可安装的明确版本，检查轮子/编译依赖、运行数据文件和系统工具。包名不能由 import 名机械替换；不直接复制旧版 vendored requirements。
5. 镜像中的固定依赖探针在相同限制下验证安装与最小运行；它们不执行数据集代码。兼容性问题记录受影响的任务/评估层，不自动换 Python 小版本系列、删题或放宽隔离。SAST 软依赖的状态与功能测试的硬依赖分开记录。

### 4.2 构建和固定镜像

1. 采用 CPython 3.14 的 Linux 基础镜像，构建时固定实际 patch 版本、架构与基础镜像摘要；先核实可用版本，再写入锁定文件，不预填不存在的摘要。
2. 构建上下文仅含 Dockerfile、锁文件、可信入口和明确需要的运行资产；配套 `.dockerignore`。不以仓库根执行广泛 `COPY`，不将 `.env`、历史 run、全量任务、DSPy 模型缓存或 Docker 凭证加入任何镜像层。
3. 固定 Python 包、系统包及运行所需数据文件的版本和校验信息；构建产物记录来源与最终安装清单。安装与下载发生在构建准备期间，评估容器运行期间禁止联网安装或补下载。
4. 镜像预建非 root 用户，设置固定 supervisor 入口与 SIGTERM 停止信号。评测镜像不需要模型调用凭证，也不需要为执行代码安装整套 DSPy/LM 运行环境。
5. 保存构建日志、Dockerfile/锁文件/上下文哈希、实际 Python/包/系统工具信息与镜像清单。执行必须引用不可变内容标识；仅本地构建时记录并核验 `sha256` image ID，不能伪称它是 registry RepoDigest；已有分发摘要时同时记录并绑定实际 image ID。

镜像标签可作展示名称，不能单独作为运行或缓存的版本依据。依赖变化生成新镜像和新配置，向子任务 03 提供实际指纹，并重跑受影响的隔离/兼容性检查。

### 4.3 固定容器权限、挂载和网络

通过主机侧可信服务统一创建容器，先检查配置，再以 `docker inspect` 核验实际生效值。每个样本的每次执行使用新容器，禁用自动重启，不跨样本复用工作目录。

| 项目 | 落实方式 |
| --- | --- |
| 权限 | 显式非 root UID/GID、只读 rootfs、`--cap-drop=ALL`、`no-new-privileges`；保持默认 seccomp 等可用防护，禁止 privileged、额外设备和 host PID/IPC 模式 |
| 输入 | 可信协调器在专用 staging 目录物化本样本代码、测试和必要 fixture；逐文件核对哈希，以只读挂载提供给容器 |
| 临时工作区 | 独立且容量有界的 tmpfs，设置所有者和权限；`/tmp`、工作目录及 `/dev/shm` 都有明确容量。选择的 mount 选项与依赖探针一起验证 |
| 输出 | 每 attempt 独立的可写结果目录，绝不挂载整个 run、cache、ledger 或父目录；实际存储具有可验证的容量硬上限，候选代码不能改写上层已发布产物 |
| 网络 | 固定 `--network=none`，不发布端口、不挂载主机 socket、不加入主机网络；允许同一容器内 loopback 测试服务，其生命周期和资源受本样本限制 |
| 环境 | 仅注入 locale、临时目录及已声明运行选项等白名单；不继承模型密钥、代理配置或主机 `PYTHONPATH`，不加载项目 `.env` |
| 主机接口 | 容器不接触仓库根、用户目录、凭证、Docker socket 或其他样本/阶段目录；输入不接收符号链接、设备、FIFO 或越界路径 |

输出目录优先使用宿主机已提供的配额存储；没有时可由可信操作者准备容量固定的独立 tmpfs，再为本次执行分配目录并限制并发。规划/普通 runner 不自动挂载主机文件系统。存储总量边界未验证时，报告前置条件未满足；不能用定时 `du` 或只限制单文件大小代替总容量限制。工作区 tmpfs、文件大小限制和输出流限额共同防止不同写入渠道绕过限制。

需要测试服务时先采用本容器 loopback。若后续评估器确需多个容器协作，由子任务 04 提供具体需求，补充隔离设计并重验；本任务不预设可任意放开的网络接口。

Docker 的运行、用户与挂载选项以[官方运行文档](https://docs.docker.com/engine/containers/run/)为实现参考；本项目允许的组合由 D 和本计划固定，不直接开放 Docker 的全部能力。

### 4.4 资源限制、超时和进程回收

1. 使用 Docker/cgroup 显式限制内存、CPU、PID 数；配置并核验 swap 策略，避免把 `--memory` 单独当成总内存上限。文件大小/描述符等进程限制作为补充，不能代替 cgroup。资源选项参考[Docker 资源限制文档](https://docs.docker.com/engine/containers/resource_constraints/)。
2. 容器内 supervisor 启动独立进程组运行已注册的评估入口，转发 SIGTERM 并在宽限期后对进程组 SIGKILL；正常结束也处理残留子进程。容器保持独立 PID namespace，脱离原进程组的子孙由容器级停止和清理兜底。
3. 主机 supervisor 用单调时钟控制总截止时间；容器创建、启动、查询、停止和删除各自也有控制命令超时，禁止无限等待 Docker CLI。容器内计时只是补充，不能作为唯一超时防护。
4. 到期、取消或输出超限时，主机经 daemon 向容器发送 SIGTERM，等待显式宽限期，再 SIGKILL，查询停止状态并清理剩余资源。Docker stop 的主进程信号与超时行为参考[官方说明](https://docs.docker.com/reference/cli/docker/container/stop/)，不能将其等同于应用自己已经完成了进程组回收。
5. stdout/stderr 采用持续有界读取与落盘，达到上限记录截断并触发终止，不先把全部输出装入内存。Docker 日志驱动也须禁用或配置有界轮转，避免只截断应用日志而 daemon 日志仍无限增长。
6. 创建前持久化请求、deadline 和唯一容器名称，创建后记录容器 ID；附加运行所有者/run/stage/attempt 标签。主机 supervisor 在调用方进程存活期间按单调时钟执行 deadline 与回收，不只依赖调用方的 `finally`；当前 supervisor 是调用方进程内的对象、不是独立进程，调用方被 kill 后不再自动回收，遗留容器由操作者用 `recover-executions` 处理（加固项，见[用户裁定 D05](./验收记录.md#d05)）。
7. （加固项，不作为本期验收门，见[用户裁定 D05](./验收记录.md#d05)）supervisor 重启时按本项目所有权标签和持久状态核对遗留容器，先回收/确认旧 attempt，再允许重执行；当前由操作者用 `recover-executions` 手动回收，不要求自动闸门。Docker/主机故障导致当时无法确认清理时标记 `cleanup_complete=false`，恢复后核实；不承诺主机失联时仍有已验证的即时清理。
8. 所有删除只针对本次请求或已核实归属的遗留资源，不执行全局 prune。只杀 Docker CLI、删 PID 文件或写下“已清理”均不算完成；证据必须包含 daemon 查询及相关子孙进程停止情况。

### 4.5 结果落盘与退出异常并存

1. 可信 harness/supervisor 按约定写结构化结果，使用临时文件、flush/fsync、原子替换发布，并回显 sample/attempt/stage、请求/代码/测试哈希、schema 及必要附件清单。临时文件不作为完成标记。
2. 输出目录位于独立于容器生命周期的受限存储；容器停止后仍可读取。不得使用先自动删除容器再尝试拷贝结果的流程，也不能仅把唯一结果留在停止后消失的容器 tmpfs。
3. 主机收集器只读取允许的普通文件，核对文件大小、结构、身份、内容哈希和必要附件；拒绝链接、路径逃逸、旧 attempt、重复/半截结果。结果收集前先确保写入进程停止，防止边写边验；校验后的产物复制到容器不可写的主机归档目录，再原子发布执行记录。
4. 完整有效结果优先保留，同时记录 `timed_out`、退出码、OOM 或其他异常。例如探针“完整写入结果后挂死”应产生 `result_valid=true` 和超时记录；不能只因退出异常改成 unavailable。反之，退出码 0 但结果缺失/损坏仍不是完整评估。
5. 身份、结构和哈希校验用于防止错配与半成品，不证明候选代码无法干扰同容器内的测试逻辑；上层 harness 负责测试完成条件及判定，后端不把候选自行打印的 JSON 当成通过证据。
6. 主机执行记录包含实际耗时与执行 attempt，交给子任务 02/05 的统一 ledger 使用；本任务不另建成本账本或结果缓存。生成失败等上游无需执行的样本不创建容器，其指标语义由上层保持。

## 5. 隔离前置检查与证据

按阶段统一验收组织一组共享、受控探针，避免为每个模块另建测试套件。先完成纯配置/路径负例，再以相同生产执行后端运行固定探针；探针入口只允许可信操作者选择预置 probe ID，不能被方法用作绕过运行门的任意执行接口。

| 映射 | 检查场景 | 必须保存的证据 |
| --- | --- | --- |
| AC-01 | 非 root、只读 rootfs、capabilities/提权限制、独立命名空间 | 实际 inspect 配置及容器内 UID/能力/写入受拒的探针结果 |
| AC-01 | 主机文件、凭证与其他样本不可访问 | 在未挂载目录放置无敏感内容的随机哨兵；读取/路径穿越被拒，环境中无凭证变量，容器内无 Docker socket。只用假凭证，不读取真实密钥作测试 |
| AC-01 | 外网不可达、本容器 loopback 可按配置使用 | network mode、接口/路由和有界连接检查；覆盖 DNS 与直接 IP 路径，失败不能只归因于某个外部站点恰好停机 |
| AC-01 | 内存、CPU、PID、工作区/输出容量和日志上限生效 | 有上界的固定压力探针、cgroup/存储配置及实际限制事件；CPU 配额以节流证据核对，不要求它触发进程退出 |
| AC-01 / AC-03 | 挂死、忽略 SIGTERM、产生子孙或新会话 | SIGTERM→SIGKILL 轨迹、daemon 状态、残留检查；覆盖正常入口退出但子孙仍活跃的情况 |
| AC-01 / AC-03 | 完整结果后挂死、半截 JSON、错身份/哈希、缺必要附件 | 完整结果在终止后可读且异常同时保留；半成品和错配结果被拒；退出码 0 不掩盖损坏 |
| AC-03 | kill 调用方、监管服务重启恢复 | 独立 supervisor 按期限收尾，重启后精确定位旧容器；不同时启动同一旧 attempt，不删除无关资源 |
| AC-02 / AC-04 执行部分 | 样本目录隔离、search/holdout 物化隔离、依赖不可用 | 各 attempt 输入/输出无交叉；缺 Docker、镜像或硬依赖有明确原因。该结果仅验证执行后端，不冒充方法受限路径验收 |

若某项限制或依赖无法在当前环境中验证，记录未执行/阻塞及影响范围，不能用 stub 的成功结果填写 AC-01。依赖探针的通过只证明所列依赖可用，数据集测试语义与裸函数体可调用性仍由子任务 03 验证。

前置证据绑定实际 host/daemon、内核与资源控制环境、镜像 ID、执行配置、挂载/存储策略、执行器/supervisor 源码和探针版本哈希。后续执行入口检查这些绑定与当前配置一致；发生变化时重跑受影响检查，不能仅凭目录内存在 `passed=true` 继续执行。机器检查通过与人工阶段验收分别记录。

## 6. 拟提供的命令与产物

以下为实施后的 CLI 设计，不是已经存在或已经执行的命令。复用既有退出码约定：成功为 0，检查阻塞为 1，配置/用法错误为 2。

```text
coco-attack check-execution --config <执行配置> --audit-dir <阶段01审计产物> --output-dir <新的检查目录>
coco-attack verify-isolation --config <执行配置> --audit-dir <阶段01审计产物> --output-dir <新的证据目录>
coco-attack recover-executions --config <执行配置> --run-dir <已有执行目录>
```

`check-execution` 核对主机能力、镜像与配置；`verify-isolation` 仅运行固定探针并产出 AC-01 证据；`recover-executions` 核对已有 manifest 的所有权和配置后收尾。镜像构建通过 `docker/evaluator/` 的明确入口和最小上下文完成，运行时不自动拉取可变标签或隐式重建镜像。

最少产物如下，名称可与子任务 05 统一，但每项含义应保留：

- `dependency_inventory.json`：依赖来源、包名映射、锁定版本、覆盖/不可用说明。
- `image_manifest.json`：基础/最终镜像身份、构建和安装信息、源码/锁文件哈希。
- `execution_profile.json`：不可变的实际资源、安全、挂载和网络配置。
- `isolation_checks.json`、`manifest.json`、`REPORT.md`：检查结果、输入与环境绑定、实际命令、时间、限制、日志/产物引用；报告不包含真实凭证。
- 每 attempt 的请求、`execution.json`、经校验的结果/附件及有界日志；容器结束后保留主机归档，临时 staging/输出存储仅在归档完成后清理。

统一写入 CLI 显式指定的目录，与只读资产和输入快照分离。新检查使用新目录；恢复入口只处理其 manifest 绑定的已有执行，不能静默覆盖其他 run。

## 7. 推进顺序与交接条件

1. 核对现有审计清单和依赖来源，固定执行请求、结果信封及目录边界；与子任务 02/03/04 对齐身份、入口和结果 schema。
2. 完成最小镜像与依赖锁、主机配置检查和资源存储前置条件；只运行可信依赖探针。
3. 实现容器生命周期、独立监管、进程组与容器级回收，再接通有界结果收集、归档和恢复。
4. 使用同一后端运行第 5 节共享探针，先形成 AC-01 证据，再开放生成代码的执行入口；缺 Docker 或隔离失败时拒绝该入口，上层可按 D 继续静态流程并报告 unavailable。
5. 向子任务 03 交付执行 API、镜像/配置指纹、原始执行分类、结果 schema 验证入口及探针证据，供其接入真实功能 harness、裸函数体检查和缓存。新增 harness 或依赖改变镜像/执行边界时补验相应项目。
6. 向子任务 04 交付相同后端、入口注册约束及 loopback 服务边界；向子任务 02 交付可信调用接口和执行 attempt 事实，不向方法进程提供 Docker 访问权。
7. 向子任务 05 交付复现命令、环境和镜像清单、AC-01 及恢复证据、已知限制与未执行项，汇入阶段记录；不得以本任务完成宣称第二阶段整体通过。

本任务的交接条件是：固定配置下的执行服务可运行，隔离前置检查具有可审查证据，超时/退出异常与完整结果可以同时保留，回收和中断恢复能核实，且调用方能获得所需接口和版本信息。Docker 不可用、强制限制未生效或清理未确认时，执行能力仍处于阻塞；阶段完成条件继续以阶段概述及人工验收结论为准。

<a id="ac01-probe-oracle"></a>
## 8. AC-01 探针预期与通过条件（实施补充）

AC-01 的验收判定以[阶段概述 AC-01](./阶段概述.md#acceptance-criteria)的 5 项要求为准（用户裁定 [D05](./验收记录.md#d05)）；本节探针条目、资源数值和挂载实例是当前开发环境的实现参考，随环境变化，不作为独立的验收门。

本节把第 5 节共享探针的机器可判定口径固定下来，作为 `verify-isolation` 的判定 oracle 和人工验收对照表。`isolation_checks.json` 中每个探针同时记录三类证据：容器内 payload checks、宿主侧 `docker inspect` 派生的 `hardening`、以及执行事实（`result_valid` / `timed_out` / `cleanup_complete` / `error_class`）。任一探针 pass 需要三类同时满足（`payload_invalid`/`identity_rejected` 例外见下）。

| probe_id | entry | 期望 expectation | 通过条件（全部满足） |
| --- | --- | --- | --- |
| identity | probe | result_valid | 信封有效且未超时；`hardening.ok`（`ReadonlyRootfs`、`CapDrop=ALL`、`no-new-privileges`、`network=none`、内存/swap/pids/cpu、`/in` 只读、`/out` 可写、镜像 id 一致）；payload 全部 checks 通过（uid/gid>0、`NoNewPrivs=1`、`CapEff` 全零、root 与 `/in` 挂载选项含 `ro`、`/out` 可写、无 docker.sock） |
| host_access | probe | result_valid | 同上 hardening；payload 通过：`read_control_ok`（正向对照，必须能读到 `/in/request.json`）、`sentinel_unreadable`、`traversal_confined`、`no_credential_env`、`docker_socket_absent`、`mount_inventory` 非空；且宿主对 `mount_inventory` 的禁止路径核对（仓库路径/`.env`/`docker.sock`/`.git`）无命中 |
| network | probe | result_valid | 同上 hardening；payload 通过：所有外部目标连接失败、所有 DNS 失败、loopback 成功（多目标，不以单站点停机为准） |
| resources | probe | result_valid | 同上 hardening；payload 通过且**逐项等于 profile**：`memory.max`、`memory.swap.max`、`pids.max`、`cpu.max`、`/tmp`、`/work`、`/dev/shm` 容量（`resource_mismatches` 为空） |
| hang_after_result | probe | result_valid_and_timed_out | 信封有效、`timed_out=true`、`cleanup_complete=true`、payload checks 通过（结果先写完再忽略 SIGTERM，二者必须并存） |
| hang_ignoring_sigterm | probe | timed_out_and_cleaned | `timed_out=true`、`cleanup_complete=true`、payload checks 通过（含 `grandchild_started`，确认新会话子孙场景确实发生） |
| partial_payload | probe | payload_invalid | 信封身份/schema/nonce 有效（`result_valid=true`）且 `payload_valid=false`（半截 payload 被拒） |
| wrong_identity | probe_raw | identity_rejected | `result_valid=false` 且 `validation_failure` 以 `result_identity_mismatch` 开头，`cleanup_complete=true` |

补充口径：

- `hardening` 来自 `docker inspect` 的实际 `HostConfig`/`Mounts`，不采信容器自报；探针 payload 是辅助证据。
- 探针请求使用 `purpose=isolation_probe`、`evaluation_layer=probe`、`probe_id`，不进入正式 sample/repeat 统计；沿用 `stage` 仅在执行身份上占位，不新增第三个实验 stage。
- 输出区为宿主预挂、有容量上限的 tmpfs（当前实例 `/run/user/1000`，`size≈1.5 GiB`、`nr_inodes≈394972`）；`check-execution` 核对容量、inode 数与内存预算，执行结果在校验后即刻归档到持久 run 目录再释放 tmpfs。主机重启导致未归档结果丢失时，恢复按 sample 重做。
- 结论按实际检查范围填写；sentinel/traversal 属辅助证据，宿主文件隔离的主证据是 HostConfig、挂载清单核对与输出收集的链接/路径拒绝。
