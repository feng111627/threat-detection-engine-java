package com.github.feng111627.threatdetectionenginejava.model;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 待检测的安全事件（本地构造，字段值不可变）。
 *
 * <p>{@code eventTime} 是事件发生时间（event time），引擎的窗口判定只使用它，
 * 与事件被处理的墙钟时间无关，从而支持乱序/迟到事件。
 */
public final class SecurityEvent {

    private final String eventId;
    private final String eventType;
    private final String entityId;
    private final Instant eventTime;
    private final Map<String, Object> attributes;

    public SecurityEvent(String eventId, String eventType, String entityId,
                         Instant eventTime, Map<String, Object> attributes) {
        this.eventId = eventId;
        this.eventType = eventType;
        this.entityId = entityId;
        this.eventTime = eventTime;
        this.attributes = attributes == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
    }

    public String getEventId() { return eventId; }
    public String getEventType() { return eventType; }
    public String getEntityId() { return entityId; }
    public Instant getEventTime() { return eventTime; }
    public Map<String, Object> getAttributes() { return attributes; }

    /**
     * 按规则字段引用取值：裸名取标准字段，{@code attr.x} 取扩展属性。
     * @return 字段值；不存在返回 null
     */
    public Object getField(String field) {
        if (field == null) {
            return null;
        }
        if (field.startsWith(EventSchema.ATTR_PREFIX)) {
            return attributes.get(field.substring(EventSchema.ATTR_PREFIX.length()));
        }
        return switch (field) {
            case "eventId" -> eventId;
            case "eventType" -> eventType;
            case "entityId" -> entityId;
            case "eventTime" -> eventTime;
            default -> attributes.get(field);
        };
    }
}
