package com.github.feng111627.threatdetectionenginejava.engine;

import com.github.feng111627.threatdetectionenginejava.model.SecurityEvent;
import com.github.feng111627.threatdetectionenginejava.rule.CompiledRule;
import com.github.feng111627.threatdetectionenginejava.rule.RuleRegistry;
import com.github.feng111627.threatdetectionenginejava.rule.RuleSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 核心检测引擎：对事件按当前规则集快照做状态关联评估。
 *
 * <p>时间语义：窗口判定完全基于事件时间（{@code eventTime}），与处理墙钟时间无关，
 * 因此乱序、迟到事件都会被归入其事件时间所属的滚动窗口：
 * <pre>windowStart = floor(eventTime.toEpochMilli() / windowMs) * windowMs</pre>
 *
 * <p>一致性：
 * <ul>
 *   <li>每次评估开始读取一次不可变 {@link RuleSet} 快照，整个评估只使用这一个版本；</li>
 *   <li>每个 (规则, 实体, 窗口) 用 {@link WindowState} 保存状态；对同一状态对象
 *       {@code synchronized} 串行化，保证并发评估下计数、去重、告警结论一致；</li>
 *   <li>同一 eventId 重复投递不重复计数；每个窗口至多告警一次（不重复、不漏）。</li>
 * </ul>
 */
public final class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);

    private final RuleRegistry registry;

    // key = ruleId|entityId|windowStartEpochMs
    private final Map<String, WindowState> windows = new ConcurrentHashMap<>();

    public DetectionEngine(RuleRegistry registry) {
        this.registry = Objects.requireNonNull(registry);
    }

    public EvaluationResult evaluate(SecurityEvent event) {
        Objects.requireNonNull(event, "event");
        if (event.getEventTime() == null) {
            throw new IllegalArgumentException("事件 eventTime 不能为空（窗口判定依赖事件时间）");
        }

        // 只读取一次快照：本次评估全部规则来自同一个版本，杜绝半集视图
        RuleSet snapshot = registry.current();
        long eventMs = event.getEventTime().toEpochMilli();

        List<Alert> alerts = new ArrayList<>();
        int duplicateDropped = 0;

        for (CompiledRule rule : snapshot.getRules()) {
            if (!rule.getFilter().matches(event)) {
                continue;
            }
            String entityId = resolveEntityId(rule, event);
            long windowMs = rule.getWindow().toMillis();
            long windowStartMs = Math.floorDiv(eventMs, windowMs) * windowMs;
            String key = rule.getId() + '|' + entityId + '|' + windowStartMs;

            WindowState state = windows.computeIfAbsent(key, k -> new WindowState());
            Alert alert;
            synchronized (state) {
                boolean isNew = state.observe(event.getEventId());
                if (!isNew) {
                    duplicateDropped++;
                    log.debug("重复事件已去重 rule={} entity={} eventId={}",
                            rule.getId(), entityId, event.getEventId());
                    continue;
                }
                int count = state.count();
                if (count >= rule.getThreshold() && state.markAlerted()) {
                    List<String> contributors = List.copyOf(state.eventIds());
                    Instant start = Instant.ofEpochMilli(windowStartMs);
                    Instant end = start.plus(rule.getWindow());
                    alert = new Alert(
                            rule.getId() + ':' + entityId + ':' + windowStartMs,
                            rule.getId(), rule.getName(), entityId,
                            windowStartMs, start, end,
                            rule.getThreshold(), count,
                            contributors, event.getEventTime());
                    log.info("触发告警 rule={} entity={} windowStart={} observed={}/threshold={} events={}",
                            rule.getId(), entityId, start, count, rule.getThreshold(), contributors);
                } else {
                    alert = null;
                }
            }
            if (alert != null) {
                alerts.add(alert);
            }
        }

        return new EvaluationResult(event.getEventId(), alerts, duplicateDropped, snapshot.getVersion());
    }

    private String resolveEntityId(CompiledRule rule, SecurityEvent event) {
        Object value = event.getField(rule.getEntityField());
        return value == null ? "<null>" : String.valueOf(value);
    }

    /** 清空关联状态（测试与重置用）。 */
    public void resetState() {
        windows.clear();
    }

    /** 当前保留的窗口状态数量（测试观察用）。 */
    public int activeWindowCount() {
        return windows.size();
    }
}
