package com.github.feng111627.threatdetectionenginejava.tests.detection;

import com.github.feng111627.threatdetectionenginejava.detection.rule.DetectionRule;
import com.github.feng111627.threatdetectionenginejava.detection.rule.RuleLoadResult;
import com.github.feng111627.threatdetectionenginejava.detection.rule.RuleRegistry;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 场景：规则集运行时更新。
 * 覆盖：合法更新原子生效、坏规则更新失败保留旧规则集、
 * 并发读取期间任何一次评估只能看到完整旧集或完整新集。
 */
class RuleHotUpdateTest {

    private static final Logger log = LoggerFactory.getLogger(RuleHotUpdateTest.class);

    private static String rule(String id, int threshold) {
        return """
                {
                  "id": "%s",
                  "description": "规则 %s",
                  "eventType": "login",
                  "entityField": "sourceIp",
                  "field": "status",
                  "op": "EQ",
                  "value": "failure",
                  "threshold": %d,
                  "windowMillis": 300000
                }
                """.formatted(id, id, threshold);
    }

    @Test
    void validReloadAtomicallyReplacesRules() {
        RuleRegistry registry = new RuleRegistry();
        RuleLoadResult first = registry.reload("[" + rule("r1", 3) + "]");
        RuleLoadResult second = registry.reload("[" + rule("r2", 5) + "," + rule("r3", 7) + "]");
        log.info("[用例] 合法热更新 -> 第一次 {} 条, 第二次 {} 条, 当前 {}",
                first.rules().size(), second.rules().size(),
                registry.currentRules().stream().map(DetectionRule::id).toList());
        assertFalse(first.hasErrors());
        assertFalse(second.hasErrors());
        assertEquals(List.of("r2", "r3"),
                registry.currentRules().stream().map(DetectionRule::id).toList());
    }

    @Test
    void failedReloadKeepsOldRules() {
        RuleRegistry registry = new RuleRegistry();
        registry.reload("[" + rule("r1", 3) + "]");
        // 新规则集里有一条引用了不存在的字段 -> 整体拒绝
        RuleLoadResult result = registry.reload(
                "[" + rule("r2", 5) + "," + rule("r3", 7).replace("\"status\"", "\"ghost\"") + "]");
        log.info("[用例] 含坏规则的热更新 -> 错误 {} 条, 当前规则 {}",
                result.errors().size(),
                registry.currentRules().stream().map(DetectionRule::id).toList());
        assertTrue(result.hasErrors());
        assertEquals(List.of("r1"),
                registry.currentRules().stream().map(DetectionRule::id).toList());
    }

    @Test
    void concurrentReadersSeeConsistentSnapshot() throws InterruptedException {
        RuleRegistry registry = new RuleRegistry();
        registry.reload("[" + rule("old-a", 3) + "," + rule("old-b", 3) + "]");
        String newRules = "[" + rule("new-a", 5) + "," + rule("new-b", 5) + "," + rule("new-c", 5) + "]";

        int readers = 8;
        int rounds = 2_000;
        ExecutorService pool = Executors.newFixedThreadPool(readers + 1);
        CountDownLatch start = new CountDownLatch(1);
        List<String> violations = new ArrayList<>();
        Set<Set<String>> observed = new HashSet<>();

        for (int i = 0; i < readers; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int r = 0; r < rounds; r++) {
                        List<DetectionRule> snapshot = registry.currentRules();
                        Set<String> ids = new HashSet<>();
                        snapshot.forEach(rule -> ids.add(rule.id()));
                        synchronized (observed) {
                            observed.add(ids);
                        }
                        boolean isOld = ids.equals(Set.of("old-a", "old-b"));
                        boolean isNew = ids.equals(Set.of("new-a", "new-b", "new-c"));
                        if (!isOld && !isNew) {
                            synchronized (violations) {
                                violations.add("看到半更新状态: " + ids);
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        pool.submit(() -> {
            try {
                start.await();
                for (int r = 0; r < 200; r++) {
                    registry.reload(newRules);
                    registry.reload("[" + rule("old-a", 3) + "," + rule("old-b", 3) + "]");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        log.info("[用例] 并发热更新 -> 违规 {} 次, 观察到的快照组合 {}",
                violations.size(), observed);
        assertTrue(violations.isEmpty(), () -> "出现半更新状态: " + violations);
        assertEquals(2, observed.size(), "读线程应同时观察到过旧集与新集");
    }
}
