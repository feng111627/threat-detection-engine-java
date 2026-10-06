package com.github.feng111627.threatdetectionenginejava.detection.engine;

import com.github.feng111627.threatdetectionenginejava.detection.model.Alert;
import com.github.feng111627.threatdetectionenginejava.detection.model.SecurityEvent;
import com.github.feng111627.threatdetectionenginejava.detection.rule.DetectionRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 检测引擎：对每条事件，按调用方传入的规则集快照做状态关联评估。
 * 同一次评估只使用同一份快照，因此并发评估在规则热更新期间结论一致
 * （要么全部旧规则，要么全部新规则）。
 */
public class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);

    /** (ruleId|entityKey) -> 窗口状态。 */
    private final ConcurrentHashMap<String, EntityWindowState> states = new ConcurrentHashMap<>();

    /**
     * 评估一条事件，返回本次触发的告警（可能为空）。
     * 同一事件重复评估是幂等的（按 eventId 去重）。
     */
    public List<Alert> evaluate(SecurityEvent event, List<DetectionRule> rulesSnapshot) {
        List<Alert> alerts = new ArrayList<>();
        for (DetectionRule rule : rulesSnapshot) {
            if (!matches(event, rule)) {
                continue;
            }
            String entityKey = event.attribute(rule.entityField());
            if (entityKey == null) {
                continue;
            }
            String stateKey = rule.id() + "|" + entityKey;
            EntityWindowState state = states.computeIfAbsent(
                    stateKey, k -> new EntityWindowState(rule.windowMillis()));

            List<SecurityEvent> matched;
            synchronized (state) {
                matched = state.addAndEvaluate(event);
                if (matched == null || !state.tryActivateAlert(matched, rule.threshold())) {
                    continue;
                }
            }
            Alert alert = buildAlert(rule, entityKey, matched);
            log.info("触发告警: rule={} entity={} window=[{},{}] events={}",
                    rule.id(), entityKey, alert.windowStart(), alert.windowEnd(),
                    alert.matchedEventIds());
            alerts.add(alert);
        }
        return alerts;
    }

    private boolean matches(SecurityEvent event, DetectionRule rule) {
        if (!rule.eventType().equals(event.eventType())) {
            return false;
        }
        String actual = event.attribute(rule.field());
        if (actual == null) {
            return false;
        }
        return switch (rule.op()) {
            case EQ -> actual.equals(rule.value());
            case NE -> !actual.equals(rule.value());
            case CONTAINS -> actual.contains(rule.value());
        };
    }

    private Alert buildAlert(DetectionRule rule, String entityKey, List<SecurityEvent> matched) {
        long start = matched.stream().mapToLong(SecurityEvent::timestamp).min().orElse(0);
        long end = matched.stream().mapToLong(SecurityEvent::timestamp).max().orElse(0);
        List<String> eventIds = matched.stream().map(SecurityEvent::eventId).sorted().toList();
        String fingerprint = rule.id() + "|" + entityKey + "|" + start + "|" + String.join(",", eventIds);
        return new Alert(rule.id(), entityKey, start, end, eventIds,
                rule.description(), fingerprint);
    }
}
