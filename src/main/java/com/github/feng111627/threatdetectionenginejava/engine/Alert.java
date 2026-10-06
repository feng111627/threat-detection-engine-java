package com.github.feng111627.threatdetectionenginejava.engine;

import com.github.feng111627.threatdetectionenginejava.rule.CompiledRule;
import java.time.Instant;
import java.util.List;

/** 一次告警（可解释：含触发规则、实体、窗口、参与事件）。 */
public record Alert(String alertId, String ruleId, String ruleName, String entityId,
                    long windowStartEpochMs, Instant windowStart, Instant windowEnd,
                    int threshold, int observedCount, List<String> contributingEventIds,
                    Instant triggeredAt) {
}
