# 本地威胁检测规则引擎

基于 Spring Boot 的本地威胁检测引擎：用本地构造的事件数据模拟待检测行为，
支持规则加载校验、事件时间窗口的多事件状态关联、规则集热更新，
并保证并发评估下检测结论一致且可解释。

## 规则格式

规则集为 JSON 数组，每条规则字段如下：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 规则唯一标识，批内不可重复 |
| `description` | 否 | 描述，会带入告警 |
| `eventType` | 是 | 匹配的事件类型 |
| `entityField` | 是 | 实体分组字段（同一实体的事件进入同一窗口状态） |
| `field` | 是 | 条件匹配字段 |
| `op` | 是 | 条件操作符：`EQ` / `NE` / `CONTAINS` |
| `value` | 是 | 条件比较值 |
| `threshold` | 是 | 窗口内匹配事件数阈值，正整数 |
| `windowMillis` | 是 | 滑动窗口大小（毫秒），正数 |

`entityField` / `field` 只能引用已知事件字段：
`eventId, eventType, sourceIp, user, host, action, status`。

示例（同一来源 IP 5 分钟内 3 次登录失败）：

```json
[
  {
    "id": "brute-force-login",
    "description": "同一来源 IP 5 分钟内 3 次登录失败",
    "eventType": "login",
    "entityField": "sourceIp",
    "field": "status",
    "op": "EQ",
    "value": "failure",
    "threshold": 3,
    "windowMillis": 300000
  }
]
```

### 校验失败原因（可区分，不静默跳过）

每条坏规则都会记录一条带类别的错误（`RuleFormatException.Reason`），
且不影响同批其他规则的解析：

- `SYNTAX_ERROR`：JSON 语法错误或规则集不是数组（此时整批无法解析）；
- `MISSING_FIELD`：必填字段缺失；
- `UNKNOWN_FIELD`：`entityField` / `field` 引用了不存在的事件字段；
- `INVALID_VALUE`：取值非法（如 `threshold <= 0`、未知 `op`）；
- `DUPLICATE_ID`：规则 id 在批内重复。

## 窗口与时间语义

- **事件时间优先**：窗口判定只使用事件的 `timestamp`（事件时间），与处理时间无关。
- **滑动窗口**：每个（规则, 实体）维护水位线 `watermark` = 已见最大事件时间，
  当前窗口为 `[watermark - windowMillis + 1, watermark]`。
- **乱序到达**：乱序事件按事件时间插入，只要落在当前窗口内就参与计数；
  早于 `watermark - windowMillis` 的迟到事件视为已过期，忽略。
- **重复投递**：按 `eventId` 去重，重复事件不改变计数、不触发额外告警。
- **告警去重（episode 语义）**：一次告警覆盖其触发事件集合，
  在这些事件全部滑出窗口之前同一（规则, 实体）不再重复告警；
  全部滑出后，新的 episode 会触发新告警 —— 跨窗口边界既不重复告警也不漏告警。
- **告警可解释**：`Alert` 携带 `ruleId`、`entityKey`、窗口起止（事件时间）、
  命中事件 id 列表和去重指纹 `fingerprint`。

## 规则更新的一致性保证

- 规则集存放在 `AtomicReference<不可变 List>` 中，更新是**整体原子替换**：
  进行中的评估要么看到完整旧规则集，要么看到完整新规则集，
  绝不看到只加载了一半的中间状态。
- 更新时先完整解析并校验新规则集；**任一规则失败则整体拒绝**，
  原规则集保持不变，并返回每条失败规则的可区分错误明细。
- 单次事件评估在评估开始时取一次快照，评估过程中不受并发更新影响。

## REST 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/detection/events` | 摄入一条事件，返回本次触发的告警 |
| `POST` | `/api/detection/rules/reload` | 热更新规则集；存在坏规则时返回 400 与错误明细，原规则集不变 |
| `GET` | `/api/detection/rules` | 查看当前生效规则集 |
| `GET` | `/api/detection/alerts` | 查看累计告警 |

## 本地验证

```bash
# 运行全部单元测试（18 个用例）
mvn test
```

测试日志中带 `[用例]` 前缀的行标出每个场景的结果，覆盖三条主流程：

- `RuleParserTest`（规则校验）：合法规则、JSON 语法错误、必填字段缺失、
  引用不存在字段、非法取值、id 重复、坏规则不拖垮整批；
- `StateCorrelationTest`（状态关联）：阈值触发、乱序到达、重复投递、
  跨窗口边界、事件时间语义、跨窗口新 episode、多实体隔离；
- `RuleHotUpdateTest`（规则热更新）：合法更新原子生效、
  失败更新保留旧规则集、8 读线程 × 2000 轮并发热更新无半更新状态。

启动应用（`mvn spring-boot:run`）后，`LocalEventSimulator` 会自动构造本地事件
（含乱序与重复投递）走一遍检测流程，日志中可看到两次 episode 各触发一条告警。
