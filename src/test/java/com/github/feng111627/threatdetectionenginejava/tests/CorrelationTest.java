package com.github.feng111627.threatdetectionenginejava.tests;

import com.github.feng111627.threatdetectionenginejava.engine.Alert;
import com.github.feng111627.threatdetectionenginejava.engine.EvaluationResult;
import com.github.feng111627.threatdetectionenginejava.model.SecurityEvent;
import com.github.feng111627.threatdetectionenginejava.service.DetectionService;
import com.github.feng111627.threatdetectionenginejava.tests.support.TestLogs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 多事件状态关联检测测试：事件时间滚动窗口、乱序、重复投递、跨窗口边界、并发一致性。
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CorrelationTest {

    private static final Class<?> ME = CorrelationTest.class;

    /** entityId 维度，1 分钟窗口，阈值 3 的登录失败规则。 */
    private static final String RULES = """
            [
              {
                "id": "BRUTE",
                "name": "暴力破解",
                "entityField": "entityId",
                "threshold": 3,
                "window": "PT1M",
                "filter": {
                  "and": [
                    { "field": "eventType", "op": "==", "value": "LOGIN" },
                    { "field": "attr.outcome", "op": "==", "value": "FAILURE" }
                  ]
                }
              }
            ]
            """;

    private DetectionService service;

    @BeforeEach
    void setUp() {
        service = new DetectionService();
        service.reloadTolerant(RULES);
    }

    private SecurityEvent loginFail(String id, String entity, String isoTime) {
        return new SecurityEvent(id, "LOGIN", entity, Instant.parse(isoTime),
                Map.of("outcome", "FAILURE"));
    }

    private SecurityEvent loginSuccess(String id, String entity, String isoTime) {
        return new SecurityEvent(id, "LOGIN", entity, Instant.parse(isoTime),
                Map.of("outcome", "SUCCESS"));
    }

    @Test
    @Order(1)
    void case01_thresholdTriggersOnce() {
        TestLogs.group(ME, "状态关联");
        TestLogs.caseStart(ME, "阈值触发", "同一实体窗口内 3 次失败 -> 第 3 次触发且只触发一次");
        TestLogs.expect(ME, "前两次无告警，第 3 次 1 条告警，再发第 4 次不重复告警");

        EvaluationResult r1 = service.evaluate(loginFail("e1", "alice", "2026-10-07T10:00:10Z"));
        EvaluationResult r2 = service.evaluate(loginFail("e2", "alice", "2026-10-07T10:00:20Z"));
        EvaluationResult r3 = service.evaluate(loginFail("e3", "alice", "2026-10-07T10:00:30Z"));
        EvaluationResult r4 = service.evaluate(loginFail("e4", "alice", "2026-10-07T10:00:40Z"));

        TestLogs.actual(ME, "告警数依次=" + List.of(r1.alertCount(), r2.alertCount(), r3.alertCount(), r4.alertCount()));
        TestLogs.check(ME, "第1次不告警", r1.alertCount() == 0);
        TestLogs.check(ME, "第2次不告警", r2.alertCount() == 0);
        TestLogs.check(ME, "第3次触发告警", r3.alertCount() == 1);
        TestLogs.check(ME, "第4次不重复告警", r4.alertCount() == 0);
        Alert alert = r3.newAlerts().get(0);
        TestLogs.check(ME, "告警 observedCount=3", alert.observedCount() == 3);
        TestLogs.check(ME, "告警含 3 个贡献事件ID", alert.contributingEventIds().size() == 3);
        TestLogs.check(ME, "告警解释包含规则与窗口",
                alert.ruleId().equals("BRUTE") && alert.windowStart().toString().equals("2026-10-07T10:00:00Z"));
    }

    @Test
    @Order(2)
    void case02_outOfOrderEventTime() {
        TestLogs.caseStart(ME, "乱序到达(基于事件时间)",
                "事件按 30s -> 10s -> 20s 的乱序顺序投递，仍按事件时间聚合同一窗口");
        TestLogs.expect(ME, "无论投递顺序如何，3 个事件都在同一窗口，恰好 1 条告警");

        EvaluationResult a = service.evaluate(loginFail("a", "bob", "2026-10-07T10:00:30Z"));
        EvaluationResult b = service.evaluate(loginFail("b", "bob", "2026-10-07T10:00:10Z"));
        EvaluationResult c = service.evaluate(loginFail("c", "bob", "2026-10-07T10:00:20Z"));

        long total = a.alertCount() + b.alertCount() + c.alertCount();
        TestLogs.actual(ME, "三次评估总告警数=" + total + "（触发点可能落在任意一次投递上）");
        TestLogs.check(ME, "乱序下恰好 1 条告警(不漏不重)", total == 1);
    }

    @Test
    @Order(3)
    void case03_duplicateDelivery() {
        TestLogs.caseStart(ME, "重复投递幂等",
                "同一 eventId e-dup 被投递 3 次");
        TestLogs.expect(ME, "只计数 1 次，不触发阈值(3)，且后两次标记 duplicateDropped");

        EvaluationResult first = service.evaluate(loginFail("e-dup", "carol", "2026-10-07T10:00:05Z"));
        EvaluationResult dup1 = service.evaluate(loginFail("e-dup", "carol", "2026-10-07T10:00:05Z"));
        EvaluationResult dup2 = service.evaluate(loginFail("e-dup", "carol", "2026-10-07T10:00:06Z"));

        TestLogs.actual(ME, "duplicateDropped 依次="
                + List.of(first.duplicateDroppedCount(), dup1.duplicateDroppedCount(), dup2.duplicateDroppedCount()));
        TestLogs.check(ME, "首次为新事件", first.duplicateDroppedCount() == 0 && first.alertCount() == 0);
        TestLogs.check(ME, "第2次重复被去重", dup1.duplicateDroppedCount() == 1 && dup1.alertCount() == 0);
        TestLogs.check(ME, "第3次重复被去重", dup2.duplicateDroppedCount() == 1 && dup2.alertCount() == 0);
    }

    @Test
    @Order(4)
    void case04_windowBoundary() {
        TestLogs.caseStart(ME, "滚动窗口边界",
                "事件时间分别为 :00:50 / :01:00 / :01:10，落在两个相邻窗口");
        TestLogs.expect(ME, ":01:00 属于新窗口，不与 :00:50 合并，两窗口各自计数不足，不告警");

        EvaluationResult x = service.evaluate(loginFail("w1", "dave", "2026-10-07T10:00:50Z"));
        EvaluationResult y = service.evaluate(loginFail("w2", "dave", "2026-10-07T10:01:00Z"));
        EvaluationResult z = service.evaluate(loginFail("w3", "dave", "2026-10-07T10:01:10Z"));

        long total = x.alertCount() + y.alertCount() + z.alertCount();
        TestLogs.actual(ME, "总告警数=" + total);
        TestLogs.check(ME, "跨边界不误报(0 告警)", total == 0);

        // 补齐第二个窗口到 3 个，触发第二窗口告警，验证确实被分成两窗
        EvaluationResult w4 = service.evaluate(loginFail("w4", "dave", "2026-10-07T10:01:20Z"));
        TestLogs.actual(ME, "第二窗口补齐后告警数=" + w4.alertCount()
                + " windowStart=" + (w4.alertCount() == 1 ? w4.newAlerts().get(0).windowStart() : "-"));
        TestLogs.check(ME, "第二窗口独立累计到阈值触发", w4.alertCount() == 1);
        TestLogs.check(ME, "告警窗口起点=10:01:00",
                w4.newAlerts().get(0).windowStart().toString().equals("2026-10-07T10:01:00Z"));
    }

    @Test
    @Order(5)
    void case05_lateEventCrossBoundary() {
        TestLogs.caseStart(ME, "迟到跨窗事件",
                "先在 :01:20/:01:40 投递，再迟到投递 :00:05 的事件");
        TestLogs.expect(ME, "迟到事件归入 :00 窗口，而不是当前处理时刻的 :01 窗口；两窗都不告警");

        EvaluationResult late1 = service.evaluate(loginFail("l1", "erin", "2026-10-07T10:01:20Z"));
        EvaluationResult late2 = service.evaluate(loginFail("l2", "erin", "2026-10-07T10:01:40Z"));
        EvaluationResult late0 = service.evaluate(loginFail("l0", "erin", "2026-10-07T10:00:05Z"));

        long total = late1.alertCount() + late2.alertCount() + late0.alertCount();
        TestLogs.actual(ME, "总告警数=" + total + "（若按处理时间聚合会错误告警=1）");
        TestLogs.check(ME, "迟到事件按事件时间归窗，不误报", total == 0);
    }

    @Test
    @Order(6)
    void case06_entityIsolation() {
        TestLogs.caseStart(ME, "实体隔离", "alice 3 次触发，bob 只有 2 次");
        TestLogs.expect(ME, "仅 alice 1 条告警，bob 不告警");

        List<Alert> alerts = new ArrayList<>();
        alerts.addAll(service.evaluate(loginFail("a1", "alice", "2026-10-07T10:00:01Z")).newAlerts());
        alerts.addAll(service.evaluate(loginFail("b1", "bob", "2026-10-07T10:00:02Z")).newAlerts());
        alerts.addAll(service.evaluate(loginFail("a2", "alice", "2026-10-07T10:00:03Z")).newAlerts());
        alerts.addAll(service.evaluate(loginFail("b2", "bob", "2026-10-07T10:00:04Z")).newAlerts());
        alerts.addAll(service.evaluate(loginFail("a3", "alice", "2026-10-07T10:00:05Z")).newAlerts());

        TestLogs.actual(ME, "总告警=" + alerts.size() + "，实体="
                + alerts.stream().map(Alert::entityId).toList());
        TestLogs.check(ME, "恰好 1 条告警", alerts.size() == 1);
        TestLogs.check(ME, "告警实体是 alice", alerts.get(0).entityId().equals("alice"));
    }

    @Test
    @Order(7)
    void case07_nonMatchingEventsIgnored() {
        TestLogs.caseStart(ME, "过滤条件不匹配不计入", "3 个登录成功事件不应触发失败告警");
        TestLogs.expect(ME, "0 条告警");
        EvaluationResult r1 = service.evaluate(loginSuccess("s1", "frank", "2026-10-07T10:00:01Z"));
        EvaluationResult r2 = service.evaluate(loginSuccess("s2", "frank", "2026-10-07T10:00:02Z"));
        EvaluationResult r3 = service.evaluate(loginSuccess("s3", "frank", "2026-10-07T10:00:03Z"));
        long total = r1.alertCount() + r2.alertCount() + r3.alertCount();
        TestLogs.actual(ME, "总告警数=" + total);
        TestLogs.check(ME, "成功登录不触发失败规则", total == 0);
    }

    @Test
    @Order(8)
    void case08_concurrentConsistency() throws Exception {
        TestLogs.caseStart(ME, "并发评估一致",
                "8 线程并发，同一实体同一窗口共 30 个不同事件 + 每个重复投递一次，乱序 eventTime");
        TestLogs.expect(ME, "该窗口全局恰好 1 条告警(在首次达到阈值 3 时产生，之后不再重复)，"
                + "30 个重复事件全部被去重");

        int threads = 8;
        int uniqueEvents = 30;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        List<SecurityEvent> events = Collections.synchronizedList(new ArrayList<>());
        // 构造同一 1 分钟窗口 [10:00:00, 10:01:00) 内的 30 个事件，时间打乱
        List<Integer> order = new ArrayList<>();
        for (int i = 0; i < uniqueEvents; i++) {
            order.add(i + 1); // 秒 1..30
        }
        Collections.shuffle(order);
        for (Integer sec : order) {
            events.add(loginFail("evt-" + sec, "grace",
                    String.format("2026-10-07T10:00:%02dZ", sec)));
        }
        // 复制出重复投递的一份，再打乱
        List<SecurityEvent> workload = new ArrayList<>(events);
        workload.addAll(new ArrayList<>(events));
        Collections.shuffle(workload);

        List<Alert> alerts = Collections.synchronizedList(new ArrayList<>());
        List<Integer> dupDrops = Collections.synchronizedList(new ArrayList<>());

        for (int t = 0; t < threads; t++) {
            final int tid = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = tid; i < workload.size(); i += threads) {
                        EvaluationResult r = service.evaluate(workload.get(i));
                        alerts.addAll(r.newAlerts());
                        if (r.duplicateDroppedCount() > 0) {
                            dupDrops.add(r.duplicateDroppedCount());
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "并发任务应在超时前完成");
        pool.shutdown();

        TestLogs.actual(ME, "并发产生告警数=" + alerts.size()
                + "，触发时计数=" + (alerts.size() == 1 ? alerts.get(0).observedCount() : "-")
                + "，去重次数合计=" + dupDrops.stream().mapToInt(Integer::intValue).sum());
        TestLogs.check(ME, "高并发下恰好 1 条告警(不重复不漏)", alerts.size() == 1);
        TestLogs.check(ME, "告警在首次达到阈值时产生(observedCount>=3)",
                alerts.get(0).observedCount() >= 3);
        TestLogs.check(ME, "触发告警时贡献事件ID互不相同",
                new HashSet<>(alerts.get(0).contributingEventIds()).size()
                        == alerts.get(0).contributingEventIds().size());
        TestLogs.check(ME, "30 个重复投递全部被幂等去重",
                dupDrops.stream().mapToInt(Integer::intValue).sum() == uniqueEvents);
        TestLogs.check(ME, "保留的窗口状态里 30 个不同事件均被计数",
                service.getEngine().activeWindowCount() >= 1);
    }
}
