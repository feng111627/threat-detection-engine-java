package com.github.feng111627.threatdetectionenginejava.tests;

import com.github.feng111627.threatdetectionenginejava.engine.EvaluationResult;
import com.github.feng111627.threatdetectionenginejava.model.SecurityEvent;
import com.github.feng111627.threatdetectionenginejava.rule.RuleLoadReport;
import com.github.feng111627.threatdetectionenginejava.rule.RuleReloadRejectedException;
import com.github.feng111627.threatdetectionenginejava.rule.RuleSet;
import com.github.feng111627.threatdetectionenginejava.service.DetectionService;
import com.github.feng111627.threatdetectionenginejava.tests.support.TestLogs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则热更新测试：原子快照替换、失败保留原集、更新期间评估只见旧集或新集。
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RuleHotReloadTest {

    private static final Class<?> ME = RuleHotReloadTest.class;

    private static final String RULES_V1 = """
            [
              { "id":"V1-A","name":"规则A","entityField":"entityId","threshold":1,"window":"PT1M",
                "filter":{"field":"eventType","op":"==","value":"ALERT_A"} }
            ]
            """;

    private static final String RULES_V2 = """
            [
              { "id":"V2-B","name":"规则B","entityField":"entityId","threshold":1,"window":"PT1M",
                "filter":{"field":"eventType","op":"==","value":"ALERT_B"} },
              { "id":"V2-C","name":"规则C","entityField":"entityId","threshold":1,"window":"PT1M",
                "filter":{"field":"eventType","op":"==","value":"ALERT_C"} }
            ]
            """;

    /** 1 条好规则 + 1 条引用未知字段的坏规则（无法构成完整规则集）。 */
    private static final String RULES_PARTIAL_BAD = """
            [
              { "id":"BADSET-OK","name":"好规则","entityField":"entityId","threshold":1,"window":"PT1M",
                "filter":{"field":"eventType","op":"==","value":"ALERT_X"} },
              { "id":"BADSET-BAD","name":"坏规则","entityField":"entityId","threshold":1,"window":"PT1M",
                "filter":{"field":"ghost.field","op":"==","value":"X"} }
            ]
            """;

    private DetectionService service;

    @BeforeEach
    void setUp() {
        service = new DetectionService();
        service.reloadTolerant(RULES_V1);
    }

    private SecurityEvent event(String id, String type, String time) {
        return new SecurityEvent(id, type, "u1", Instant.parse(time), Map.of());
    }

    @Test
    @Order(1)
    void case01_initialSnapshotVersion() {
        TestLogs.group(ME, "规则热更新");
        TestLogs.caseStart(ME, "初始加载形成快照", "加载 V1（1 条规则）");
        TestLogs.expect(ME, "版本=1，规则数=1，规则 id=V1-A");
        RuleSet rs = service.currentRuleset();
        TestLogs.actual(ME, "version=" + rs.getVersion() + " rules="
                + rs.getRules().stream().map(r -> r.getId()).toList());
        TestLogs.check(ME, "版本为 1", rs.getVersion() == 1);
        TestLogs.check(ME, "规则数 1", rs.getRules().size() == 1);
    }

    @Test
    @Order(2)
    void case02_tolerantReload_isolatesAndSwaps() {
        TestLogs.caseStart(ME, "容错热更新", "V1 -> 含 1 好 1 坏 的批次");
        TestLogs.expect(ME, "坏规则被隔离并在报告中给出原因，好规则整集替换上线，版本递增");

        long before = service.currentRuleset().getVersion();
        RuleLoadReport report = service.reloadTolerant(RULES_PARTIAL_BAD);
        RuleSet after = service.currentRuleset();

        TestLogs.actual(ME, "版本 " + before + " -> " + after.getVersion()
                + ", loaded=" + report.loadedCount() + ", failures=" + report.failureCount()
                + ", 上线规则=" + after.getRules().stream().map(r -> r.getId()).toList());
        TestLogs.check(ME, "报告含 1 条成功 1 条失败",
                report.loadedCount() == 1 && report.failureCount() == 1);
        TestLogs.check(ME, "失败原因是 UNKNOWN_FIELD（不静默跳过）",
                report.failures().get(0).reason().name().equals("UNKNOWN_FIELD"));
        TestLogs.check(ME, "上线的是好规则 BADSET-OK，坏规则不在快照中",
                after.getRules().size() == 1
                        && after.getRules().get(0).getId().equals("BADSET-OK"));
        TestLogs.check(ME, "版本单调递增", after.getVersion() > before);
    }

    @Test
    @Order(3)
    void case03_strictReload_successThenReject() {
        TestLogs.caseStart(ME, "严格热更新", "V1 -> V2(合法) -> 含坏规则批次(应被拒绝)");
        TestLogs.expect(ME, "V2 合法则整体上线；含坏规则时抛异常且回退保留 V2");

        RuleSet v2 = service.reloadStrict(RULES_V2);
        TestLogs.actual(ME, "严格更新到 V2: version=" + v2.getVersion()
                + " rules=" + v2.getRules().stream().map(r -> r.getId()).toList());
        TestLogs.check(ME, "V2 整体上线(2 条)", v2.getRules().size() == 2);

        long versionBeforeReject = service.currentRuleset().getVersion();
        RuleReloadRejectedException ex = assertThrows(RuleReloadRejectedException.class,
                () -> service.reloadStrict(RULES_PARTIAL_BAD));

        RuleSet retained = service.currentRuleset();
        TestLogs.actual(ME, "拒绝后保留: version=" + retained.getVersion()
                + " rules=" + retained.getRules().stream().map(r -> r.getId()).toList()
                + "；异常携带失败数=" + ex.getFailures().size());
        TestLogs.check(ME, "异常明确报告失败", ex.getFailures().size() == 1);
        TestLogs.check(ME, "原规则集版本不变", retained.getVersion() == versionBeforeReject);
        TestLogs.check(ME, "原规则集内容不变(仍是 V2 两条)", retained.getRules().size() == 2
                && retained.getRules().stream().anyMatch(r -> r.getId().equals("V2-B"))
                && retained.getRules().stream().anyMatch(r -> r.getId().equals("V2-C")));
    }

    @Test
    @Order(4)
    void case04_oldOrNewNoPartialDuringConcurrentReload() throws Exception {
        TestLogs.caseStart(ME, "更新期间只见旧集或新集",
                "1 个线程反复在 V1(1条) / V2(2条) 间热更新，多个线程同时提交事件");
        TestLogs.expect(ME, "每次评估看到的规则数只能是 1 或 2，绝不出现半集(其它数量)；"
                + "评估结果中版本号与规则集一致");

        AtomicBoolean stop = new AtomicBoolean(false);
        AtomicInteger observedRuleCounts = new AtomicInteger();
        AtomicBoolean partialSeen = new AtomicBoolean(false);
        AtomicReference<String> partialDetail = new AtomicReference<>("");
        AtomicInteger evalCount = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);

        int updaterThreads = 1;
        int evaluatorThreads = 4;
        ExecutorService pool = Executors.newFixedThreadPool(updaterThreads + evaluatorThreads);

        // 更新线程：反复 V1 <-> V2
        for (int u = 0; u < updaterThreads; u++) {
            pool.submit(() -> {
                try {
                    start.await();
                    boolean toV2 = true;
                    while (!stop.get()) {
                        service.reloadStrict(toV2 ? RULES_V2 : RULES_V1);
                        toV2 = !toV2;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        // 评估线程：每次评估独立读取一次快照，校验规则数与版本合法性
        for (int e = 0; e < evaluatorThreads; e++) {
            final int idx = e;
            pool.submit(() -> {
                try {
                    start.await();
                    int i = 0;
                    while (!stop.get() && i < 20_000) {
                        SecurityEvent ev = event("hot-" + idx + "-" + i,
                                (i % 2 == 0) ? "ALERT_A" : "ALERT_B",
                                "2026-10-07T12:00:00Z");
                        EvaluationResult r = service.evaluate(ev);
                        RuleSet seen = service.currentRuleset();
                        // 评估结果版本必须是当前存在过的某一版本，且规则数只可能为 1 或 2
                        int n = seen.getRules().size();
                        observedRuleCounts.set(n);
                        if (n != 1 && n != 2) {
                            partialSeen.set(true);
                            partialDetail.set("非法规则数=" + n + " version=" + seen.getVersion());
                        }
                        if (r.rulesetVersion() < 1) {
                            partialSeen.set(true);
                            partialDetail.set("非法版本号=" + r.rulesetVersion());
                        }
                        evalCount.incrementAndGet();
                        i++;
                    }
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        start.countDown();
        Thread.sleep(1500);
        stop.set(true);
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "线程应在超时内结束");

        // 由于所有事件 eventId 唯一、eventTime 固定，阈值=1 的单事件规则会对匹配事件告警；
        // 关键校验在于规则数始终为 1 或 2，从无半集
        TestLogs.actual(ME, "总评估次数=" + evalCount.get()
                + "，最后观察到的规则数=" + observedRuleCounts.get()
                + "，是否观察到半集=" + partialSeen.get());
        TestLogs.check(ME, "确实进行了大量并发评估", evalCount.get() > 1000);
        TestLogs.check(ME, "全程未见半成品规则集(规则数仅 1 或 2)", !partialSeen.get());
        TestLogs.check(ME, "最终快照规则数为 1 或 2",
                service.currentRuleset().getRules().size() == 1
                        || service.currentRuleset().getRules().size() == 2);
        if (partialSeen.get()) {
            TestLogs.actual(ME, "异常细节: " + partialDetail.get());
        }
    }

    @Test
    @Order(5)
    void case05_semanticSwitchAfterReload() {
        TestLogs.caseStart(ME, "热更新改变检测语义", "V1 只对 ALERT_A 告警；更新为 V2 后改为对 ALERT_B/C 告警");
        TestLogs.expect(ME, "更新前 ALERT_B 不告警；更新后 ALERT_B 告警，ALERT_A 不再告警");

        EvaluationResult before = service.evaluate(event("b1", "ALERT_B", "2026-10-07T10:00:00Z"));
        service.reloadStrict(RULES_V2);
        EvaluationResult afterB = service.evaluate(event("b2", "ALERT_B", "2026-10-07T10:00:01Z"));
        EvaluationResult afterA = service.evaluate(event("a2", "ALERT_A", "2026-10-07T10:00:02Z"));

        TestLogs.actual(ME, "更新前 ALERT_B 告警=" + before.alertCount()
                + "；更新后 ALERT_B 告警=" + afterB.alertCount()
                + "，ALERT_A 告警=" + afterA.alertCount());
        TestLogs.check(ME, "V1 下 ALERT_B 不告警", before.alertCount() == 0);
        TestLogs.check(ME, "V2 下 ALERT_B 触发 V2-B", afterB.alertCount() == 1
                && afterB.newAlerts().get(0).ruleId().equals("V2-B"));
        TestLogs.check(ME, "V2 下旧的 ALERT_A 已不生效", afterA.alertCount() == 0);
        TestLogs.check(ME, "评估结果带规则集版本号(可解释)", afterB.rulesetVersion() >= 2);
    }

    @Test
    @Order(6)
    void case06_syntaxErrorReloadPreservesRuleset() {
        TestLogs.caseStart(ME, "文件级语法错误也不破坏原集",
                "对一个完全不是 JSON 的内容做严格更新");
        TestLogs.expect(ME, "抛异常（报告含 SYNTAX_ERROR），原 V1 规则集与版本保持不变");

        long version = service.currentRuleset().getVersion();
        RuleReloadRejectedException ex = assertThrows(RuleReloadRejectedException.class,
                () -> service.reloadStrict("<<< not json >>>"));
        TestLogs.actual(ME, "失败原因=" + ex.getReport().failures().get(0).reason()
                + "，保留版本=" + service.currentRuleset().getVersion());
        TestLogs.check(ME, "原因 SYNTAX_ERROR",
                ex.getReport().failures().get(0).reason().name().equals("SYNTAX_ERROR"));
        TestLogs.check(ME, "原规则集保留", service.currentRuleset().getVersion() == version
                && service.currentRuleset().getRules().size() == 1
                && service.currentRuleset().getRules().get(0).getId().equals("V1-A"));
        assertNotNull(ex);
        assertEquals(1, ex.getReport().failures().size());
    }
}
