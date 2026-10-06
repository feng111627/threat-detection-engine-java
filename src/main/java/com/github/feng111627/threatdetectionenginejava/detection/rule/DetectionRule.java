package com.github.feng111627.threatdetectionenginejava.detection.rule;

/**
 * 检测规则：在 windowMillis 事件时间窗口内，同一实体（entityField 取值）
 * 满足条件（field op value）的 eventType 事件数达到 threshold 即告警。
 */
public record DetectionRule(
        String id,
        String description,
        String eventType,
        String entityField,
        String field,
        ConditionOp op,
        String value,
        int threshold,
        long windowMillis) {

    public enum ConditionOp {
        EQ, NE, CONTAINS
    }
}
