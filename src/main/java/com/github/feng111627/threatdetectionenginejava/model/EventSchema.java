package com.github.feng111627.threatdetectionenginejava.model;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 事件字段 schema：声明规则可引用的标准字段及其类型。
 *
 * <p>字段引用有两类：
 * <ul>
 *   <li>标准字段（裸名，如 eventType）：必须在 schema 中声明，否则规则校验报 UNKNOWN_FIELD；</li>
 *   <li>扩展属性（{@code attr.} 前缀，如 attr.sourceIp）：取自事件 attributes，
 *       schema 不做静态存在性检查；但可以通过 instantAttributes 声明其中哪些是时间类型，
 *       以便规则中的时间字符串被解析为 {@link java.time.Instant}。</li>
 * </ul>
 */
public final class EventSchema {

    /** 扩展属性引用前缀。 */
    public static final String ATTR_PREFIX = "attr.";

    private final Map<String, FieldType> fields;
    private final Set<String> instantAttributes;

    public EventSchema(Map<String, FieldType> fields) {
        this(fields, Set.of());
    }

    public EventSchema(Map<String, FieldType> fields, Set<String> instantAttributes) {
        this.fields = Map.copyOf(fields);
        this.instantAttributes = Set.copyOf(instantAttributes);
    }

    /** 默认 schema：事件的 4 个标准字段。 */
    public static EventSchema defaultSchema() {
        Map<String, FieldType> std = new LinkedHashMap<>();
        std.put("eventId", FieldType.STRING);
        std.put("eventType", FieldType.STRING);
        std.put("entityId", FieldType.STRING);
        std.put("eventTime", FieldType.INSTANT);
        return new EventSchema(std, Set.of());
    }

    /** 该字段引用是否已知（标准字段已声明，或显式 attr.* 动态属性）。 */
    public boolean exists(String field) {
        if (field == null) {
            return false;
        }
        return fields.containsKey(field) || field.startsWith(ATTR_PREFIX);
    }

    public Optional<FieldType> fieldType(String field) {
        return Optional.ofNullable(fields.get(field));
    }

    public Map<String, FieldType> fields() {
        return fields;
    }

    /** 动态属性是否按时间类型解析（传入字段引用全名，如 attr.loginAt）。 */
    public boolean isInstantAttribute(String fieldReference) {
        if (fieldReference == null || !fieldReference.startsWith(ATTR_PREFIX)) {
            return false;
        }
        String name = fieldReference.substring(ATTR_PREFIX.length());
        return instantAttributes.contains(name) || instantAttributes.contains(fieldReference);
    }
}
