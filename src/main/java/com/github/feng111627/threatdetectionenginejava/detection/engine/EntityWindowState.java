package com.github.feng111627.threatdetectionenginejava.detection.engine;

import com.github.feng111627.threatdetectionenginejava.detection.model.SecurityEvent;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

/**
 * 单个（规则, 实体）维度的事件时间滑动窗口状态。
 *
 * 语义：
 * - 窗口由事件时间水位线 watermark（已见最大事件时间）界定：
 *   [watermark - windowMillis + 1, watermark]，与处理时间无关。
 * - 按 eventId 去重，重复投递不改变计数。
 * - 乱序事件按事件时间插入，只要落在当前窗口内就参与计数。
 * - 告警按“ episode ”去重：一次告警覆盖其触发事件集合，
 *   直到这些事件全部滑出窗口后才允许同一实体再次告警，
 *   避免窗口滑动造成重复告警，也避免跨窗口漏告警。
 */
class EntityWindowState {

    private final long windowMillis;
    /** 事件时间 -> 该时刻的事件列表（按 eventId 去重后）。 */
    private final TreeMap<Long, List<SecurityEvent>> eventsByTime = new TreeMap<>();
    private final Set<String> seenEventIds = new HashSet<>();
    /** 当前生效告警覆盖的事件 id 集合；为空表示无生效告警。 */
    private Set<String> activeAlertEventIds = Set.of();
    private long watermark = Long.MIN_VALUE;

    EntityWindowState(long windowMillis) {
        this.windowMillis = windowMillis;
    }

    /**
     * 插入事件并评估当前窗口。
     *
     * @return 触发告警时返回告警覆盖的事件列表（按时间升序）；否则返回 null
     */
    synchronized List<SecurityEvent> addAndEvaluate(SecurityEvent event) {
        if (seenEventIds.contains(event.eventId())) {
            return null; // 重复投递：忽略
        }
        if (watermark != Long.MIN_VALUE && event.timestamp() <= watermark - windowMillis) {
            return null; // 已滑出窗口的迟到事件：忽略
        }
        seenEventIds.add(event.eventId());
        eventsByTime.computeIfAbsent(event.timestamp(), k -> new ArrayList<>()).add(event);
        watermark = Math.max(watermark, event.timestamp());
        pruneExpired();

        List<SecurityEvent> inWindow = eventsInWindow();
        if (inWindow.isEmpty()) {
            return null;
        }
        // 清理已失效的告警：其触发事件全部滑出窗口
        if (!activeAlertEventIds.isEmpty()
                && inWindow.stream().noneMatch(e -> activeAlertEventIds.contains(e.eventId()))) {
            activeAlertEventIds = Set.of();
        }
        return inWindow;
    }

    /** 当前窗口内计数达到阈值且没有生效告警时，登记新告警。 */
    synchronized boolean tryActivateAlert(List<SecurityEvent> matched, int threshold) {
        if (matched.size() < threshold || !activeAlertEventIds.isEmpty()) {
            return false;
        }
        Set<String> ids = new HashSet<>();
        for (SecurityEvent e : matched) {
            ids.add(e.eventId());
        }
        activeAlertEventIds = ids;
        return true;
    }

    private List<SecurityEvent> eventsInWindow() {
        long from = watermark - windowMillis + 1;
        List<SecurityEvent> result = new ArrayList<>();
        for (List<SecurityEvent> bucket : eventsByTime.tailMap(from, true).values()) {
            result.addAll(bucket);
        }
        return result;
    }

    private void pruneExpired() {
        long cutoff = watermark - windowMillis;
        var head = eventsByTime.headMap(cutoff, true);
        for (List<SecurityEvent> bucket : head.values()) {
            for (SecurityEvent e : bucket) {
                seenEventIds.remove(e.eventId());
            }
        }
        head.clear();
    }
}
