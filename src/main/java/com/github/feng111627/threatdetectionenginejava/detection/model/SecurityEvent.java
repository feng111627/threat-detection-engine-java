package com.github.feng111627.threatdetectionenginejava.detection.model;

import java.util.Map;

/**
 * 待检测的安全事件。timestamp 为事件时间（epoch millis），窗口判定基于它而非处理时间。
 */
public record SecurityEvent(
        String eventId,
        String eventType,
        long timestamp,
        Map<String, String> attributes) {

    public String attribute(String key) {
        return attributes == null ? null : attributes.get(key);
    }
}
