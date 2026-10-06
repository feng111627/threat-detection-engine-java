package com.github.feng111627.threatdetectionenginejava.detection.model;

import java.util.List;

/**
 * 检测结论。fingerprint 为去重键：同一规则、同一实体、同一窗口只告警一次。
 */
public record Alert(
        String ruleId,
        String entityKey,
        long windowStart,
        long windowEnd,
        List<String> matchedEventIds,
        String description,
        String fingerprint) {
}
