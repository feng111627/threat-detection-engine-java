# 本地威胁检测规则引擎

一个基于 Spring Boot 的**本地**威胁检测规则引擎：用本地构造的安全事件模拟需要被检测的行为，
重点保证三件事在**规则热更新、多事件状态关联、并发评估**下结论一致且可解释：

1. **规则加载与校验**：语法错误、必填缺失、引用不存在字段等问题不静默跳过，给出可区分的失败原因；一条坏规则不会让整批规则失效。
2. **多事件状态关联**：同一实体的多个事件按**事件时间（event time）滚动窗口**关联；乱序到达、重复投递、跨窗口边界都不会重复告警或漏告警。
3. **规则热更新**：运行时整集原子替换；更新期间正在进行的评估要么看到旧规则集、要么看到新规则集，绝不会看到只加载了一半的规则集；更新失败保留原规则集并明确报错。

---

## 1. 快速开始

```bash
# 编译
mvn -o compile

# 运行全部单测（27 个用例，场景/用例/期望/实际/断言直接打印到控制台）
mvn -o test

# 打包并启动（默认从 classpath:rules/sample-rules.json 加载 3 条示例规则）
mvn -o package -DskipTests
java -jar target/threat-detection-engine-java-1.0-SNAPSHOT.jar --server.port=8080
```

启动后可访问 `GET /api/detection/rules` 查看当前生效规则集版本与规则。

---

## 2. 规则格式

规则文件是一个 **JSON 数组**（也支持 `{"rules": [ ... ]}` 包裹形式），每个元素是一条规则：

```json
[
  {
    "id": "RULE-BRUTE-FORCE",
    "name": "登录暴力破解",
    "description": "同一账号 1 分钟内登录失败达到 5 次",
    "entityField": "entityId",
    "threshold": 5,
    "window": "PT1M",
    "filter": {
      "and": [
        { "field": "eventType", "op": "==", "value": "LOGIN" },
        { "field": "attr.outcome", "op": "==", "value": "FAILURE" }
      ]
    }
  }
]
```

### 2.1 顶层字段

| 字段 | 必填 | 说明 |
|---|---|---|
| `id` | 是 | 规则唯一标识，同一批次内重复会被判为 `DUPLICATE_RULE_ID`（只保留第一条） |
| `name` | 是 | 规则名称（告警中回显，便于解释） |
| `description` | 否 | 规则描述 |
| `entityField` | 是 | **关联实体字段**。裸名（`entityId`）取事件标准字段；`attr.xxx` 取扩展属性，如按来源 IP 聚合用 `attr.sourceIp`。引用不存在的标准字段报 `UNKNOWN_FIELD` |
| `threshold` | 否，默认 `1` | 窗口内去重事件数达到该阈值即告警；必须为整数且 `>= 1`，否则 `INVALID_VALUE` |
| `window` | 是 | 滚动窗口长度：正整数毫秒（`60000`）或 ISO-8601 时长字符串（`PT1M`、`PT30S`）；缺失/非法/非正分别报 `MISSING_REQUIRED_FIELD`、`SYNTAX_ERROR`、`INVALID_VALUE` |
| `filter` | 否 | 过滤条件，省略表示匹配全部事件。可以是单个叶子条件，或 `{"and": [ ... ]}` 组合 |

### 2.2 条件与运算符

叶子条件：`{"field": ..., "op": ..., "value": ...}`

- `field`：事件字段引用。
  - **标准字段（裸名）**：`eventId` / `eventType` / `entityId` / `eventTime`，由事件 schema 声明；引用未声明的裸名字段报 `UNKNOWN_FIELD`。
  - **扩展属性**：`attr.` 前缀（如 `attr.sourceIp`、`attr.outcome`），取自事件 `attributes`；这类动态字段不做静态存在性检查（运行时缺失按 `null` 处理），但仍做运算符/值形态校验。
- `op` 支持：`==`、`!=`、`>`、`>=`、`<`、`<=`、`contains`、`startsWith`、`endsWith`、`in`。未知运算符报 `SYNTAX_ERROR`。
- `value`：字符串/数字/布尔/数组（`in`）。**不能为 null**。标准字段会校验值类型与字段声明类型及运算符是否兼容，不兼容报 `TYPE_MISMATCH`（例如对字符串字段 `eventType` 做 `>` 数字比较）。

### 2.3 校验失败原因（可区分，不静默跳过）

| 原因 `RuleFailureReason` | 触发情形 |
|---|---|
| `SYNTAX_ERROR` | 文件不是合法 JSON / 顶层结构错 / 某条规则结构错 / 未知运算符 / window 时长无法解析 |
| `MISSING_REQUIRED_FIELD` | `id`、`name`、`entityField`、`window` 或条件的 `field`/`op` 缺失为空 |
| `UNKNOWN_FIELD` | `entityField` 或条件引用了 schema 中不存在的标准字段 |
| `TYPE_MISMATCH` | 条件值类型与字段类型 / 运算符不兼容 |
| `INVALID_VALUE` | 比较值为 null、`threshold<1`、`window<=0` 等 |
| `DUPLICATE_RULE_ID` | 同一批次内规则 id 重复 |

每条坏规则独立产生一条 `RuleFailure`（含 `ruleIdHint`、批次下标 `index`、`reason`、`detail`），
坏规则被隔离，**不影响同批其他规则加载**。

---

## 3. 窗口与时间语义

### 3.1 一切基于事件时间（event time），与处理时间无关

窗口归属只由事件自带的 `eventTime`（ISO-8601，如 `2026-10-07T10:00:30Z`）决定，
**不使用事件被处理时的墙钟时间**。因此：

- **乱序到达**：先到 10:00:30、再到 10:00:10，两者仍归入同一个 `[10:00:00, 10:01:00)` 窗口；
- **迟到事件**：10:01:20 才收到一条 `eventTime=10:00:05` 的事件，它归入 10:00 窗口，而不会被错误并进“当前”窗口。

### 3.2 滚动窗口（tumbling window）

窗口为固定长度、首尾相接、互不重叠，起点按事件时间向下取整：

```
windowStartMs = floor(eventTime.toEpochMilli() / windowMs) * windowMs
窗口区间        = [windowStart, windowStart + window)
```

边界事件 `10:01:00` 属于新窗口 `[10:01:00,10:02:00)`，不会与 `10:00:50` 合并。

### 3.3 去重与“每窗至多一次告警”

状态键为 `(ruleId, entityId, windowStart)`。每个窗口状态保存：

- 窗口内**去重后的事件 ID 集合**：同一 `eventId` 重复投递只计一次（幂等），重复事件在结果中计入 `duplicateDropped`；
- `alerted` 标记：窗口内去重计数**首次达到 `threshold`** 的那次评估产生且仅产生一条告警，之后该窗口不再告警。

因此在乱序、重复投递、跨窗口边界下都做到**不重复告警、不漏告警**。
告警对象 `Alert` 具备完整可解释信息：规则 id/名称、实体、窗口起止、阈值、触发时观测数、全部贡献事件 ID。

> 说明：告警在“首次达到阈值”时产生，记录的是触发瞬间的观测值（`observedCount >= threshold`）；
> 阈值之后到达的事件继续被去重计数，但不会重复产生告警。

---

## 4. 规则更新的一致性保证

### 4.1 不可变快照 + 单次原子发布

- 当前生效规则集是一个不可变对象 `RuleSet`（带单调递增 `version` 与不可变规则列表），由 `RuleRegistry` 用一个 `volatile` 引用持有。
- 热更新时，先把新规则**全部解析、逐条校验、收集成一个新的不可变列表**，然后只做一次引用替换（snapshot swap）。
- `DetectionEngine.evaluate` 在评估开始时读取**一次** `RuleSet` 快照，整次评估只使用这一个版本。

由此保证：

- 更新期间并发进行的评估，**要么看到完整旧集，要么看到完整新集**，绝不会看到只加载了一半的规则集（半集在发布前根本不可见）；
- 每次评估结果都带 `rulesetVersion`，可以解释结论来自哪一版规则。

### 4.2 两种更新语义

| 接口 / 方法 | 坏规则处理 | 失败时 |
|---|---|---|
| **容错** `POST /api/detection/rules/reload`（`reloadTolerant`） | 坏规则隔离进报告，合法规则整集替换上线 | 文件级解析失败时返回报告，不替换 |
| **严格** `POST /api/detection/rules/reload-strict`（`reloadStrict`） | 任一规则非法即**整体拒绝**，返回 HTTP 400，**完全不触碰注册表** | 原规则集版本与内容原样保留，错误明细随响应/异常 `RuleReloadRejectedException` 返回 |

### 4.3 并发评估一致性

- 规则遍历基于不可变快照，天然无“半集”问题。
- 每个 `(规则,实体,窗口)` 的状态对象 `WindowState` 访问在同一把锁内串行化（`ConcurrentHashMap.computeIfAbsent` 取状态 + `synchronized(state)` 读改写），
  保证并发下计数、去重、`markAlerted` 的读改写是原子的，从而同一窗口全局恰好告警一次。

---

## 5. HTTP 接口

| 方法与路径 | 作用 |
|---|---|
| `GET /api/detection/rules` | 查看当前规则集版本、规则数与规则概要 |
| `POST /api/detection/rules/reload` | **容错**热更新；请求体为规则 JSON 文本；返回 loaded/failures 明细与 activeVersion |
| `POST /api/detection/rules/reload-strict` | **严格**热更新；有坏规则返回 `400` 且原规则集保留 |
| `POST /api/detection/events` | 提交一个事件进行检测，返回新告警、去重数、规则集版本 |

事件请求体：

```json
{
  "eventId": "evt-1",
  "eventType": "LOGIN",
  "entityId": "alice",
  "eventTime": "2026-10-07T10:00:30Z",
  "attributes": { "outcome": "FAILURE", "sourceIp": "10.0.0.1" }
}
```

`eventTime` 必填（窗口判定依据）；`attributes` 中的字段在规则里以 `attr.xxx` 引用。

---

## 6. 本地验证方法

### 6.1 单元测试（推荐）

```bash
mvn -o test
```

测试日志按「场景组 → 场景 → 用例 → 期望 → 实际 → 断言 PASS/FAIL」打印，可直接看出覆盖范围与每条用例结果：

- `RuleValidationTest`（12 例，规则校验主流程与边界）
  - 文件级语法错误、window 非法时长、未知运算符；
  - 缺 `id`、缺 `window` 等必填缺失；
  - filter / entityField 引用未知字段；类型不符；threshold=0、负 window；
  - 重复规则 ID；混合批次中坏规则不连累好规则。
- `CorrelationTest`（8 例，状态关联主流程与边界）
  - 阈值触发且只触发一次；乱序到达按事件时间聚合；重复投递幂等去重；
  - 滚动窗口边界；迟到跨窗事件；实体隔离；不匹配过滤不计入；
  - 8 线程并发 + 重复投递 + 乱序事件时间下，同窗口全局恰好 1 条告警。
- `RuleHotReloadTest`（6 例，热更新主流程与边界）
  - 初始快照版本；容错隔离并整集替换；严格成功 / 拒绝并保留原集；
  - 1 更新线程 + 4 评估线程高并发下规则数只可能是旧集或新集、从无半集（数万次评估）；
  - 热更新后检测语义切换；文件级语法错误也不破坏原集。
- `ApplicationTests`：Spring 上下文加载，启动时容错加载示例规则（3 条全部成功）。

### 6.2 手动 HTTP 冒烟

启动后可依次验证（示例）：

```bash
# 查看规则
curl -s http://localhost:8080/api/detection/rules

# 乱序提交 5 次登录失败（同一分钟窗口），第 5 次返回 newAlertCount=1
for t in 10:00:50 10:00:10 10:00:40 10:00:20 10:00:30; do
  curl -s -X POST http://localhost:8080/api/detection/events -H 'Content-Type: application/json' \
    -d "{\"eventId\":\"$RANDOM\",\"eventType\":\"LOGIN\",\"entityId\":\"alice\",\"eventTime\":\"2026-10-07T${t}Z\",\"attributes\":{\"outcome\":\"FAILURE\"}}"
done

# 严格热更新一条坏规则：返回 400，GET /rules 仍是原规则集
curl -i -X POST http://localhost:8080/api/detection/rules/reload-strict \
  -H 'Content-Type: application/json' \
  -d '[{"id":"X","name":"x","entityField":"entityId","window":"PT1M",
        "filter":{"field":"ghost.field","op":"==","value":"v"}}]'
```

---

## 7. 代码结构

```
model/      EventSchema(字段与类型)、SecurityEvent(事件，eventTime)、FieldType
rule/       规则语法：Condition/Leaf/And、RuleParser、RuleValidator、RuleLoader(坏规则隔离)、
            RuleRegistry(volatile 不可变快照)、RuleSet、RuleFailure(Reason)、热更新异常
engine/     DetectionEngine(event-time 滚动窗口 + 去重 + 每窗一次告警 + 并发安全)、
            WindowState、Alert、EvaluationResult
service/    DetectionService 门面（容错/严格热更新 + 评估）
web/        DetectionController（HTTP 接口）、EventRequest
bootstrap/  DefaultRuleBootstrap（启动加载 classpath 示例规则）
config/     Spring Bean 装配
```
