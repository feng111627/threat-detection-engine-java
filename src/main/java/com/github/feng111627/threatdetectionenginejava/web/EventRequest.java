package com.github.feng111627.threatdetectionenginejava.web;

import java.util.Map;

/** 事件提交请求体。 */
public final class EventRequest {
    private String eventId;
    private String eventType;
    private String entityId;
    private String eventTime; // ISO-8601
    private Map<String, Object> attributes = Map.of();

    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }
    public String getEventTime() { return eventTime; }
    public void setEventTime(String eventTime) { this.eventTime = eventTime; }
    public Map<String, Object> getAttributes() { return attributes; }
    public void setAttributes(Map<String, Object> attributes) { this.attributes = attributes; }
}
