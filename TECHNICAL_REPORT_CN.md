# GPT-5.6 混用检测器 4.1.0 技术报告

实现根目录：`gpt56_vnext/`  
报告 schema：`3`  
行为评分版本：`trusted-fingerprint-v3`  
正式基线：`baselines/trusted_fingerprint_v3.json`

## 摘要

GPT-5.6 混用检测器是一个本地运行的 API 证据采集与分类工具。它检查申报为 GPT-5.6 Sol、Terra 或 Luna 的 Responses 兼容端点，是否出现以下可观测现象：

1. Juice 命中另一个已知型号。
2. 固定的 32/48 输出被改成 `40` 或 `40...`。
3. 上游额外注入了简单的 Juice 语义覆盖。
4. 固定行为题的答案分布与可信 Sol、Terra、Luna 中某一模型高度相似。
5. 普通/Native Codex 请求、短/32K 上下文之间出现差异。

正式运行不需要可信 API。可信三模型只在离线采集阶段用于构建冻结行为基线。运行时只向用户填写的待测端点发送流式 Responses 请求。

4.1.0 的核心原则是“宁可证据不明确，也不把不完整数据硬判成混用”。确定性异常和统计指纹分别报告，不再使用混合比例模型，也不再把复杂回放门禁包装成难以解释的概率。

本报告只以项目源码、冻结资源和项目测试产物为实现依据。文末资料用于说明研究背景，不使用与本项目无关的官方文档推导实现。

## 1. 检测范围与非目标

### 1.1 正式申报型号

```text
gpt-5.6-sol
gpt-5.6-terra
gpt-5.6-luna
```

Juice 分类器额外识别 GPT-5.5、GPT-5.4、GPT-5.4-mini 的冻结指纹，以便报告旧型号混入。

### 1.2 输出是什么

检测器输出三类信息：

- 确定性证据：错误型号 Juice、40 前缀改写、明确覆盖异常。
- 相对行为证据：在冻结 Sol/Terra/Luna 指纹集合内更像谁。
- 数据质量：HTTP 尝试、成功、最终错误、取消、不完整流和各探针格完成率。

### 1.3 不试图证明什么

检测器不是远程证明协议，无法证明：

- 上游没有透明代理。
- 上游没有识别公开探针。
- 普通业务请求与探测请求一定走相同路由。
- API 申报名称一定对应某个不可伪造的物理模型实例。
- 一次通过可以代表未来持续通过。

## 2. 总体架构

```text
浏览器 Web UI
  -> 本地 HTTP 服务 server.py
  -> 配置规范化 presets.py
  -> DetectorSession detector.py
       -> SQLiteStateStore store.py
       -> StreamingResponsesClient transport.py
            -> 普通 Python 流式请求
            -> Native Codex Node 子进程
       -> Juice 分类 juice.py
       -> 行为归一化 normalizers.py
       -> 指纹评分 probability_model.py
       -> 七状态汇总 verdict.py
       -> 可选原始留存 retention.py
```

Web UI 不是权威状态源。任务、尝试、停止标记和结果都以 SQLite 为准；浏览器只轮询并展示本地服务状态。

## 3. 任务与请求协议

### 3.1 逻辑任务

检测开始前，配置被规范化并生成稳定任务清单。每个逻辑任务包含：

- `probe_id`
- 重复序号
- 思考强度
- 请求格式
- 上下文模式
- 固定题面与 developer 提示
- 可复现的 `job_id`

一个逻辑任务最多发送 `retries + 1` 次 HTTP 尝试；默认 `retries=2`，即最多 3 次。HTTP 重试不改变逻辑任务的探针身份。

### 3.2 所有请求都使用流式 Responses

正式路径不发送非流式探测。传输层增量解析 SSE：

- `response.completed`：正常终止。
- `response.failed`：上游明确失败，不进入答案评分。
- `response.incomplete`：响应不完整，不进入答案评分。
- 在终止事件前断流：记为不完整流。

正文优先使用完整终态内容；若终态正文为空但 delta 已完整拼接，可以使用 delta。终态与 delta 冲突视为协议错误。

检测器只请求用户选择的文本模型，不会调用生图接口，也不会自行改用其他模型名。

### 3.3 两种请求格式

`normal`：由 Python 构造的普通流式 Responses 请求。

`native_codex`：由 Node 传输器复现项目本地抓包中经过清理的 Codex 请求轮廓，包括相关头字段、Responses body、会话元数据和流式行为。该资源不包含个人路径、IP 或凭据。

Native 模式是应用层伪装，不保证网络层一致。出口 IP、TLS 栈和系统路由仍可能不同。需要尽量复现 Codex 网络路径时，应在系统级开启 TUN VPN；浏览器代理不一定覆盖 Python/Node 子进程。

### 3.4 两种上下文

`no_history`：不添加伪造历史。

`fixed_32k_history`：前置固定、无个人信息的历史消息，约 33,792 输入 token。

两种格式乘以两种上下文形成四个 profile：

```text
normal + no_history
normal + fixed_32k_history
native_codex + no_history
native_codex + fixed_32k_history
```

高档用这些组合检查“只对特定客户端格式给真模型”以及“仅首次/短上下文给真模型”。

## 4. Juice 确定性层

### 4.1 指纹表与共享值

Juice 与思考强度相关。分类器支持：

```text
low, medium, high, xhigh, max
```

Sol 的低/中/high 支持短值和对应长值形式；Terra、Luna 与旧型号按冻结精确值比较。部分型号在某些档位共享值，例如低档或中档的短值。

为避免误报，分类顺序固定为：

1. 规范化为一个纯数字。
2. 计算该数字兼容的全部已知型号。
3. 若申报型号在兼容集合中，分类为 `current_success`。
4. 只有申报型号不在集合、但其他已知型号在集合中，才分类为 `mixed`。
5. 未命中任何已知值，分类为 `unsuccessful`。

因此，共享值不会仅因同时兼容其他模型就报警。

### 4.2 会话级 Juice 三状态

对每个启用思考档统计：

- `current_success`
- `mixed`
- `unsuccessful`
- `network_error`

状态规则：

- `juice_pass`：没有 mixed，并且每个启用档位至少有一次 current_success。
- `juice_mixed`：至少出现一次 mixed；该事件粘住会话。
- `juice_all_unsuccessful`：每个启用档位都有足够有效完成，但全部是 unsuccessful。
- `data_insufficient`：不满足上述条件，例如某个启用档位没有申报型号命中或有效完成不足。

`juice_all_unsuccessful` 会覆盖为最终“可能非GPT”。

Juice 通过还可以带质量警告：某档只有一次申报型号命中，或全部有效请求中的申报命中率低于50%。质量警告不等于型号冲突。

### 4.3 Juice 题面

题面使用结果仍为原始 Juice 的恒等变形，不建立新数值对照表。公开包携带可审计的公开模板；内部包在同一分类逻辑上增加私有冻结模板池。

模板中的高频词采用冻结的统一拼写变体，避免同一模板同时出现多种写法而增加可识别特征。私有模板正文不进入公开包或本报告。

模板保密只增加针对成本，不是密码学保护。上游仍可伪造 Juice。

## 5. 输出完整性与覆盖探针

### 5.1 32/48 输出完整性

两个控制请求分别要求精确输出 `48` 和 `32`。分类器不做宽松数字提取：

- 原始输出精确等于目标：`current_success`。
- 原始输出是 `40` 或匹配 `40[0-9]*`：`output_rewrite_40_prefix`，硬异常。
- 其他所有内容：`unsuccessful`，仅代表证据无效。

空值、解释文字、32/48 之外的其他数字不会被误报成改写。硬异常只针对 `40` 或 40 前缀纯数字。

### 5.2 显式 Juice 覆盖探针

覆盖探针在 developer 消息中显式定义随机合成值 `N`，再要求恒等计算返回 `N`。生成 `N` 时排除：

- 全部已知 Juice 短值。
- 可能与已知长值前缀混淆的数值。
- `40` 及 40 前缀值。

分类：

- 返回 N：`explicit_value`。
- 返回 40/40...：`explicit_hidden_override`，硬异常。
- 返回其他任一已知 Juice：`known_juice_definition_ignored`，硬异常。
- 返回其他数字：`other_numeric`，不硬判。
- 非数字：`unsuccessful`。

该探针只检查“上游在用户显式 developer 定义之外又注入简单 Juice 覆盖”的一种常见对抗，不声称能读取或证明完整系统提示。

## 6. 三个内置行为探针

正式题面固定，不允许语义改写：

```text
Name a random country. Reply with ONLY the country name.

Name a random bird. Reply with ONLY the bird name, one word.

Count the letter r in strawberry. Reply only with the integer.
```

固定随机国家与固定随机鸟利用模型在“随机选择”任务中的稳定偏好分布。B80 利用字符处理差异，主要提供特定模型对的区分信息。

题面、developer 提示、思考强度、请求格式、上下文和归一化器共同构成冻结契约。修改任一项都会失去正式资格。

### 6.1 归一化

国家和鸟使用 `behavior_label`：

1. 去除首尾空白。
2. 去除最外层常见引号、反引号和标点。
3. Unicode casefold。
4. 连续空白折叠为一个空格。
5. 只接受限定长度的拉丁字母标签；不合法格式归为 `__INVALID_OUTPUT__`。
6. 基线未收录但格式合法的标签在评分时归为 `__OTHER__`。

B80 使用 `b80_exact_3`：

- 纯整数 3 -> `exact_3`
- 其他纯整数 -> `other_integer`
- 非整数 -> `__INVALID_OUTPUT__`

归一化器哈希写入运行契约，防止题面一致但分类语义漂移。

## 7. trusted-fingerprint-v3 数学模型

### 7.1 符号

对一个探针格（题面 + profile），令：

- 模型集合 `M={Sol, Terra, Luna}`。
- 类别集合为该格可信数据出现过的类别，再加 `__OTHER__` 和 `__INVALID_OUTPUT__`。
- `n[m,c]` 为可信模型 m 输出类别 c 的次数。
- 平滑常数 `alpha=0.5`。

### 7.2 0.5 平滑

可信模型 m 的类别概率：

```text
p[m,c] = (n[m,c] + 0.5) / (sum_c n[m,c] + 0.5 * |C|)
```

平滑的作用不是“放宽门槛”，而是避免从未出现过的类别获得绝对零概率。没有平滑时，一次新答案会产生负无穷对数似然，完全压倒其他证据；0.5 让未知答案仍然受到明显惩罚，但不会把一条样本变成数学上的绝对否决。

### 7.3 S：模型间差异

对 Sol/Terra/Luna 三对可信分布计算 Jensen-Shannon divergence，再取平均：

```text
S = mean(JSD(p_sol,p_terra), JSD(p_sol,p_luna), JSD(p_terra,p_luna))
```

JSD 使用以 2 为底的对数，范围 0–1。S 越大，三模型在该格越容易区分。

### 7.4 D：时间漂移

每个可信模型按时间窗分别得到平滑分布；同一模型各时间窗两两计算 JSD。D 是所有可计算模型的窗内平均漂移：

```text
D = mean(同一模型不同时间窗的两两 JSD)
```

D 越大，说明探针本身随时间不稳定。

单时间窗无法估计 D。自定义生成器会明确标为“未验证跨时间稳定性”。

### 7.5 w：参考权重

```text
if S <= 0 or S <= D:
    w = 0
else:
    w = min(1, (S - D) / S)
```

只有模型间差异大于时间漂移时，该格才贡献身份信息。w 越接近 1，表示可区分差异相对稳定；w=0 表示该格不参与正式比较。

### 7.6 每格平均对数似然

待测端在该格得到计数 `x[c]`，有效样本数为 N：

```text
LL_cell[m] = sum_c x[c] * ln(p[m,c]) / N
```

这里直接使用经过 `alpha=0.5` 平滑的可信模型分布 `p[m,c]`，不再把它向三模型共同分布收缩。这样 `w` 只在下一步合并格时使用一次，不会对低权重格二次削弱。

除以 N 很重要：它让“多发了请求的格”不会仅凭样本数更大而压倒其他探针。

### 7.7 同题不同 profile 合并

同一个 probe_id 的不同 profile 先组成一个探针家族。家族内按格的 w 对平均对数似然加权平均：

```text
LL_family[m] = sum_cell w_cell * LL_cell[m] / sum_cell w_cell
```

家族权重取该家族有效格的最大 w，最大为 1。最终模型分数是各家族贡献之和。这样四个上下文/profile 不会被当成四个完全独立题面而重复放大。

这也是 `w` 在正式评分中的唯一一次权重作用。探针生成器仍显示 S、D 和 w，便于解释某格为什么贡献较多或完全不参与。

### 7.8 T=1 softmax

最终三个分数直接使用 `T=1`：

```text
match[m] = exp(score[m]) / sum_k exp(score[k])
```

4.1.0 不再搜索或调节温度，不再把分数乘 20。显示值保留三位小数，名称固定为“指纹匹配度”。

它是三份冻结指纹之间的相对相似度，不是真实模型概率，不是账号路由比例，也不是混用比例。

## 8. 正式门禁与强指向线

### 8.1 90% 完成门禁

每个正式探针格要求：

```text
completed >= ceil(planned * 0.90)
```

计划 10 条至少完成 9 条；计划 20 条至少完成 18 条。任一必需格未达到时，行为层为“证据不明确”。一条最终错误不会再直接否决计划 20 条的探针格。

### 8.2 精确运行契约

正式评分还要求运行签名命中冻结 baseline。签名覆盖：

- probe_id 与 profile。
- 每格请求数。
- 用户题面哈希。
- developer 提示哈希。
- 思考强度。
- 请求格式与上下文模式。
- normalizer 哈希。

未命中契约仍可显示参考匹配度，但不产生正式强指向。

### 8.3 中档与高档阈值

只有一个模型严格大于对应门槛时，行为层才为 `strong_match`：

| 档位 | Sol | Terra | Luna |
|---|---:|---:|---:|
| 中 | >0.70 | >0.75 | >0.90 |
| 高 | >0.95 | >0.90 | >0.90 |

没有模型越线，或多个模型同时越线，均为 `unclear`。

低档不启用内置行为指纹，因此必然不产生正式强指向。这是“证据不明确”的正常原因，不是网络故障。自定义档位和导入的自定义探针也固定为参考模式。

### 8.4 已删除的 v4.0.1 逻辑

正式路径已完全删除：

- 温度 T 搜索。
- tau 搜索和单格 tau。
- `pass_margin` 与 `alert_margin`。
- 纯模型/混合模型比较与混合比例。
- mixture gain 及其门槛。
- 600 次模拟回放的 Wilson 指标。
- 回放覆盖率门禁。
- OOD 第 1 百分位线。
- 概率层粘性报警。

新报告不应再产生这些字段。依赖旧字段的外部脚本必须升级。

## 9. 七状态汇总

### 9.1 两个轴

Juice 轴：

```text
通过 / 与申报型号不一致 / 证据不足
```

指纹轴：

```text
强烈指向某模型 / 证据不明确
```

二者笛卡尔积得到六种结果，再由“所有启用 Juice 档位足量但全不成功”覆盖为第七种“可能非GPT”。

### 9.2 结果代码

```text
juice_pass_fingerprint_strong
juice_pass_fingerprint_unclear
juice_mismatch_fingerprint_strong
juice_mismatch_fingerprint_unclear
juice_insufficient_fingerprint_strong
juice_insufficient_fingerprint_unclear
possible_non_gpt
```

### 9.3 冲突处理

确定性层和行为层不互相覆盖。例如“Juice与申报型号不一致；指纹强烈指向 Sol”同时保留两个事实，不会因为行为层像 Sol 就抹掉错误 Juice。

“可能非GPT”只来自 Juice 全档足量但全部无法识别。普通网络错误、空响应或样本不足不会触发它。

## 10. 单次与持续模式

### 10.1 单次冻结预设

低档 14 条：

```text
high Juice 8
low Juice 3
48 控制 1
32 控制 1
覆盖 1
```

中档 64 条：

```text
high Juice 12
low/xhigh/max Juice 各6
48/32 各1
覆盖2
固定随机国家20
B80 10
```

高档 202 条：

- 除 B80 外的启用探针按四个 profile 组合发送。
- B80 只使用 `normal+no_history`。
- 各 profile 中 Juice 为 high 8、low/medium/xhigh/max 各4，32/48 各1，覆盖2，国家10，鸟10。
- B80 10 条。

### 10.2 持续模式

每轮先对每个启用探针独立抽签，再把命中的探针扩展到适用 profile。冻结本轮 manifest 后才发送，因此崩溃恢复不会重新抽签改变历史。

持续报告对每个行为格使用最近的“计划窗口”，其中包含成功和最终错误，再应用 90% 完成门禁。只取成功答案会虚增完成率，因此禁止这样做。

行为指纹不粘住：新窗口到来后重新计算。确定性的错误型号 Juice、40 前缀改写和明确覆盖异常会粘住当前会话。

## 11. 持久化、恢复与重试预算

SQLite 使用 WAL 模式和单 writer：

- `sessions` 保存配置哈希、状态和停止时间。
- `jobs` 保存冻结逻辑任务和最终结果。
- `attempts` 保存每次真实 HTTP 尝试。
- 运行统计从 SQLite 重建，而不是依赖内存计数。

恢复时：

1. 扫描未完成会话。
2. 对账崩溃遗留的 running attempt。
3. 根据持久化 attempt 数计算剩余预算。
4. 跳过已成功任务。
5. 只补发未完成且仍有预算的任务。

因此反复重启不能绕过每任务最多 3 次 HTTP 尝试。

## 12. 停止和资源生命周期

会话级取消控制器登记每个 `job_id` 的活动资源。

点击停止时：

1. SQLite 写入 `stop_requested_at`。
2. 设置会话取消事件。
3. 停止提交新任务。
4. 唤醒重试等待。
5. 普通请求关闭 HTTP response 和底层 socket。
6. Native 请求终止 Node 子进程，宽限后仍未退出则 kill。
7. 等活动请求退出后再关闭数据库。

Windows 上 `socket.makefile()` 会推迟普通 `close()` 对底层句柄的关闭；实现会先 `shutdown()`，再调用 CPython 的底层 real-close 作为兼容路径，使阻塞读取能及时退出。

取消使用独立状态，不算网络错误，也不会触发重试。

## 13. 错误分类与会话级停止

内部错误使用稳定代码，Web UI 映射成中文；只有上游原始错误正文保留原文。

- 401/403：认证或权限错误，停止派发整批任务。
- 404：地址、路径或模型不存在。
- 408/超时：请求或流等待超时。
- 429：额度、频率或并发限制。
- 5xx：上游或中转异常。
- `response_failed`：上游明确返回失败终态。
- `response_incomplete`：上游明确返回未完成终态。
- 无终止事件断流：流被代理或上游截断。
- 用户取消：不归入线路故障。
- 留存失败：立即停止，防止用户误以为证据完整。

线路错误只影响数据完整性，不直接算型号混用。

## 14. 原始请求/响应留存

可选留存按 HTTP 尝试保存不可删减的请求正文和原始响应流，并附带：

- UTC 时间。
- 会话、job 和尝试标识。
- 上游请求 ID（可取得时）。
- 去掉查询参数的目标地址。
- 请求格式、上下文、模型和思考档位。
- 状态码、延迟、首事件时间、事件数。
- 解析对象、错误类别和 SHA-256。

Authorization 与 API key 永不写入。留存目录带索引和最终完整性清单；任何写入失败都会使 `retention_complete=false` 并停止运行。

## 15. 自定义探针生成器

生成器使用同一流式传输、SQLite 任务/尝试模型和 normalizer。它采集用户指定可信三模型的类别计数，导出 schema 3 fingerprint-v3 文档。

生成器与检测器共享同一取消控制器语义：调度器每0.1秒检查停止状态，取消宽限为3秒，不使用阻塞式线程池关闭；普通流、HTTP错误正文和Native子进程均可取消。401/403会停止后续派发并把会话标记为认证失败；零成功批次不会进入“采集完成”。

导出包含：

- 精确题面与哈希。
- developer 提示与哈希。
- normalizer 配置与哈希。
- 各模型、各窗口的类别计数。
- S、D、w、JSD 和样本完整性。
- 每个探针格当前更支持 Sol、Terra 或 Luna 的贡献方向。
- 单/多时间窗与稳定性标记。

单时间窗允许导出，但 `time_stability_verified=false`。4.1.0 中自定义探针永远是参考证据：检测器可以请求、归一化、显示分布和匹配度，但不会据此产生正式强指向或改变七状态结论。

## 16. 报告 schema 3

核心块：

```text
combined_summary
juice_summary
output_integrity_summary
coverage_summary
fingerprint_summary
reference_fingerprint_results
fingerprint_window_states
network_summary
attempt_errors
retention_manifest
```

`fingerprint_summary` 包含：

```text
fingerprint_status
fingerprint_model
fingerprint_match
fingerprint_thresholds
fingerprint_official_eligible
fingerprint_unclear_reasons
fingerprint_unclear_reasons_cn
cell_summaries
family_contributions
```

前端只展示中文解释和可读表格，原始类别计数仍留在 JSON 供技术审计。

4.1.0 不再输出正式 `probability_summary`、`mixture_summary`、旧 `data_completeness`、tau、margin、回放 Wilson/覆盖率或 OOD 门禁。

## 17. 真实验证边界

项目已有本地 Plus 账号池的冻结/冒烟参考：

- 中档纯 Sol 正式完整结果：48/48 均由 Sol 排名第一，45/48 的 Sol 匹配度高于70%。
- 中档 Luna 映射：18/18 高于90%。
- 中档 Terra 映射：17/17 高于75%。
- 高档纯 Sol：13/13 高于95%；删除二次 `w` 收缩后的离线重放范围为98.866%–99.476%。

这些结果只描述对应账号池、题面、时间窗口和网络条件。账号风控、临时降级、上游改版或中转路由变化都可能使新结果漂移，不能把这些数字当成永久服务保证。

实现验证包括：

- 当前 28 项 Python 回归测试。
- 完整测试压力连续 10 轮通过。
- 正式全量测试连续 3 轮通过。
- 普通流取消连续 30 次通过。
- Python 编译和 JavaScript/Node 语法检查。
- 桌面及 390px 手机浏览器布局检查。
- 公开 staging 14 条低档本地模拟检测。
- 公开包凭据、个人路径、旧入口和私有模板扫描。

## 18. 威胁模型和限制

### 18.1 公开探针过滤

固定题面和公开算法可能被中转识别。Native/32K、模板变体和持续随机调度提高了针对成本，但不提供密码学不可区分性。

### 18.2 缓存

固定题面可能被响应缓存。报告中的答案分布、异常低延迟和重复请求可帮助人工发现，但当前七状态不把缓存检测当成独立硬证据。

### 18.3 官方或账号池临时路由

即使本地直连账号池，也可能因风控、额度、负载或产品策略出现临时路由变化。检测器描述的是观测行为，不判断变化发生在中转还是更上游。

### 18.4 Juice 可伪造

Juice 在现有确定性层中权重高，是因为可信端极少漂移到另一个已知型号值；但中转可以识别并伪造它。覆盖探针只防一种简单覆盖方式。

### 18.5 行为指纹不是绝对身份概率

匹配度的样本空间只有三个冻结参考模型。未知模型也可能偶然更像其中之一。低档、自定义配置或数据不足时系统会主动弃权。

## 19. 研究参考

以下资料影响了行为分布、低熵多 cell 指纹与随机偏好探针的研究方向；项目实现仍以本仓库源码和自身可信采集为准：

1. [One Token Is Enough: Model Fingerprinting with Low-Entropy Behavioral Cells](https://arxiv.org/html/2607.10252v1)：多 cell、类别分布与 JSD 指纹思路。
2. [Deterministic or probabilistic? LLM random-number behavior](https://arxiv.org/abs/2502.19965)：模型“随机”输出中的系统偏好。
3. [BazaarLink Probe](https://bazaarlink.ai/)：多行为单元工程组织方式的公开参考。
4. [hlwy-ai-checker](https://github.com/hanlinwenyuan/hlwy-ai-checker)：社区模型检查工具的公开实现参考。
5. [Linux.do 相关讨论](https://linux.do/t/topic/2472419)：随机偏好与模型差异的社区实测背景。

这些资料不构成本项目对某个模型身份的背书，也不替代本项目自己的可信基线和门禁。

## 20. 最终边界声明

- 加密状态层不能区分所有 Sol/Terra/Luna 情况。
- Juice 是可伪造的辅助指纹。
- 指纹匹配度不是实际概率或混用比例。
- 低档的“指纹证据不明确”通常只是没有启用该层。
- 综合通过不能排除透明代理、探针识别或普通请求差异化路由。
