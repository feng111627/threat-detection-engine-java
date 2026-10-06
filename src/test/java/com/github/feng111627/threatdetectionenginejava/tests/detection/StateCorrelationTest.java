package com.github.feng111627.threatdetectionenginejava.tests.detection;

import com.github.feng111627.threatdetectionenginejava.detection.engine.DetectionEngine;
import com.github.feng111627.threatdetectionenginejava.detection.model.Alert;
import com.github.feng111627.threatdetectionenginejava.detection.model.SecurityEvent;
import com.github.feng111627.threatdetectionenginejava.detection.rule.DetectionRule;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 场景：多事件状态关联（事件时间滑动窗口）。
 * 覆盖：窗口内达到阈值告警、乱序到达、重复投递、跨窗口边界、
 * 窗口判定基于事件时间而非处理时间、多实体相互隔离。
 */
class StateCorrelationTest {

    private static final Logger log = LoggerFactory.getLogger(StateCorrelationTest.class);
    private static final long T0 = 1_700_000_000_000L;
    private static final long WINDOW = 300_000; // 5 分钟

    /** 规则：5 分钟内同一 sourceIp 失败登录 >=3 次。 */
    private static final DetectionRule RULE = new DetectionRule(
            "brute-force", "暴力破解", "login", "sourceIp",
            "status", DetectionRule.ConditionOp.EQ, "failure", 3, WINDOW);

    private SecurityEvent fail(String id, String ip, long ts) {
        return new SecurityEvent(id, "login", ts,
                Map.of("sourceIp", ip, "user", "alice", "status", "failure"));
    }

    private List<Alert> feedAll(DetectionEngine engine, List<SecurityEvent> events) {
        List<Alert> all = new ArrayList<>();
        for (SecurityEvent e : events) {
            all.addAll(engine.evaluate(e, List.of(RULE)));
        }
        return all;
    }

    @Test
    void thresholdReachedFiresOneAlert() {
        DetectionEngine engine = new DetectionEngine();
        List<Alert> alerts = feedAll(engine, List.of(
                fail("e1", "10.0.0.1", T0),
                fail("e2", "10.0.0.1", T0 + 1_000),
                fail("e3", "10.0.0.1", T0 + 2_000)));
        log.info("[用例] 窗口内 3 次失败 -> 告警 {} 条", alerts.size());
        assertEquals(1, alerts.size());
        assertEquals(List.of("e1", "e2", "e3"), alerts.get(0).matchedEventIds());
    }

    @Test
    void outOfOrderEventsStillFireExactlyOnce() {
        DetectionEngine engine = new DetectionEngine();
        List<Alert> alerts = feedAll(engine, List.of(
                fail("e3", "10.0.0.1", T0 + 2_000),
                fail("e1", "10.0.0.1", T0),          // 乱序：最早的事件最后到
                fail("e2", "10.0.0.1", T0 + 1_000)));
        log.info("[用例] 乱序到达 -> 告警 {} 条, 事件 {}", alerts.size(),
                alerts.isEmpty() ? List.of() : alerts.get(0).matchedEventIds());
        assertEquals(1, alerts.size());
        assertEquals(List.of("e1", "e2", "e3"), alerts.get(0).matchedEventIds());
    }

    @Test
    void duplicateDeliveryDoesNotDoubleCount() {
        DetectionEngine engine = new DetectionEngine();
        List<Alert> alerts = feedAll(engine, List.of(
                fail("e1", "10.0.0.1", T0),
                fail("e2", "10.0.0.1", T0 + 1_000),
                fail("e2", "10.0.0.1", T0 + 1_000),  // 重复投递
                fail("e1", "10.0.0.1", T0)));        // 重复投递
        log.info("[用例] 重复投递 -> 告警 {} 条（期望 0，去重后只有 2 个事件）", alerts.size());
        assertEquals(0, alerts.size());
    }

    @Test
    void eventsBeyondWindowDoNotCombine() {
        DetectionEngine engine = new DetectionEngine();
        List<Alert> alerts = feedAll(engine, List.of(
                fail("e1", "10.0.0.1", T0),
                fail("e2", "10.0.0.1", T0 + 1_000),
                // 与 e1 相距超过窗口，三者不在同一窗口
                fail("e3", "10.0.0.1", T0 + WINDOW + 2_000)));
        log.info("[用例] 跨窗口边界 -> 告警 {} 条（期望 0）", alerts.size());
        assertEquals(0, alerts.size());
    }

    @Test
    void windowBasedOnEventTimeNotProcessingTime() {
        // 事件时间都在窗口内，即使“处理时刻”相隔很久（这里用多次调用模拟）也只算事件时间
        DetectionEngine engine = new DetectionEngine();
        List<Alert> alerts = feedAll(engine, List.of(
                fail("e1", "10.0.0.1", T0),
                fail("e2", "10.0.0.1", T0 + 100),
                fail("e3", "10.0.0.1", T0 + 200)));
        log.info("[用例] 事件时间在窗口内（与处理时间无关）-> 告警 {} 条", alerts.size());
        assertEquals(1, alerts.size());
        assertEquals(T0, alerts.get(0).windowStart());
        assertEquals(T0 + 200, alerts.get(0).windowEnd());
    }

    @Test
    void newEpisodeAfterWindowFiresNewAlert() {
        DetectionEngine engine = new DetectionEngine();
        List<Alert> alerts = feedAll(engine, List.of(
                fail("e1", "10.0.0.1", T0),
                fail("e2", "10.0.0.1", T0 + 1_000),
                fail("e3", "10.0.0.1", T0 + 2_000),   // 第一个 episode -> 告警
                fail("f1", "10.0.0.1", T0 + WINDOW + 10_000),
                fail("f2", "10.0.0.1", T0 + WINDOW + 11_000),
                fail("f3", "10.0.0.1", T0 + WINDOW + 12_000))); // 第二个 episode -> 新告警
        log.info("[用例] 跨窗口两个 episode -> 告警 {} 条（期望 2，不重复不漏报）", alerts.size());
        assertEquals(2, alerts.size());
        assertTrue(alerts.get(0).fingerprint().hashCode() != alerts.get(1).fingerprint().hashCode());
    }

    @Test
    void entitiesAreIsolated() {
        DetectionEngine engine = new DetectionEngine();
        List<Alert> alerts = feedAll(engine, List.of(
                fail("a1", "10.0.0.1", T0),
                fail("b1", "10.0.0.2", T0 + 100),
                fail("a2", "10.0.0.1", T0 + 200),
                fail("b2", "10.0.0.2", T0 + 300)));
        log.info("[用例] 两个实体各 2 次 -> 告警 {} 条（期望 0，互不累计）", alerts.size());
        assertEquals(0, alerts.size());
    }
}
