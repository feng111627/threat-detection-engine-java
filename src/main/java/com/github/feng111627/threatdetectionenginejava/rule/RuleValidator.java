package com.github.feng111627.threatdetectionenginejava.rule;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.github.feng111627.threatdetectionenginejava.model.EventSchema;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * 校验并编译单条规则。
 *
 * <p>每一类问题映射到一个可区分的 {@link RuleFailureReason}：
 * <ul>
 *   <li>{@code SYNTAX_ERROR}：该规则节点结构不对（非对象、filter 结构错、窗口文本无法解析等）；</li>
 *   <li>{@code MISSING_REQUIRED_FIELD}：id/name/entityField/window 等必填项缺失或为空；</li>
 *   <li>{@code UNKNOWN_FIELD}：entityField 或 filter 引用了 schema 中不存在的字段；</li>
 *   <li>{@code TYPE_MISMATCH}：条件值类型与字段/运算符不兼容；</li>
 *   <li>{@code INVALID_VALUE}：threshold/window 取值非法（0、负数等）。</li>
 * </ul>
 * 跨规则的重复 ID 由 {@link RuleLoader} 归为 {@code DUPLICATE_RULE_ID}。
 */
public final class RuleValidator {

    private final EventSchema schema;

    public RuleValidator(EventSchema schema) {
        this.schema = schema;
    }

    /** 校验+编译成功返回规则；失败抛出携带 RuleFailure 的异常。 */
    public CompiledRule validateAndCompile(RawRule raw) {
        try {
            return doCompile(raw);
        } catch (RuleValidationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new RuleValidationException(
                    new RuleFailure(raw.idHint(), raw.index(), RuleFailureReason.SYNTAX_ERROR,
                            "规则结构无法解析: " + e.getMessage()), e);
        }
    }

    private CompiledRule doCompile(RawRule raw) {
        JsonNode node = raw.node();
        if (node == null || !node.isObject()) {
            throw fail(raw, RuleFailureReason.SYNTAX_ERROR, "规则必须是一个 JSON 对象");
        }

        String id = requireText(node, "id", raw);
        String name = requireText(node, "name", raw);
        String entityField = requireText(node, "entityField", raw);

        String description = node.hasNonNull("description") ? node.get("description").asText() : "";

        if (!schema.exists(entityField)) {
            throw fail(raw, RuleFailureReason.UNKNOWN_FIELD,
                    "entityField 引用了不存在的字段: '" + entityField + "'");
        }

        int threshold = 1;
        if (node.has("threshold")) {
            JsonNode t = node.get("threshold");
            if (!t.isNumber() || !t.canConvertToInt()) {
                throw fail(raw, RuleFailureReason.INVALID_VALUE, "threshold 必须是整数");
            }
            threshold = t.intValue();
            if (threshold < 1) {
                throw fail(raw, RuleFailureReason.INVALID_VALUE,
                        "threshold 必须 >= 1，实际: " + threshold);
            }
        }

        Duration window = parseWindow(node.get("window"), raw);
        Condition filter = parseFilter(node.get("filter"));

        List<ConditionIssue> issues = filter.validate(schema);
        if (!issues.isEmpty()) {
            // 一条规则的条件可能有多个问题；全部带出，原因取第一个问题的分类
            RuleFailureReason first = issues.get(0).reason();
            String detail = String.join("; ", issues.stream().map(ConditionIssue::toString).toList());
            throw fail(raw, first, detail);
        }

        return new CompiledRule(id, name, description, entityField, threshold, window, filter);
    }

    private String requireText(JsonNode node, String field, RawRule raw) {
        JsonNode value = node.get(field);
        if (value == null || value.getNodeType() == JsonNodeType.NULL || value.asText().isBlank()) {
            throw fail(raw, RuleFailureReason.MISSING_REQUIRED_FIELD,
                    "必填字段 '" + field + "' 缺失或为空");
        }
        return value.asText();
    }

    private Duration parseWindow(JsonNode windowNode, RawRule raw) {
        if (windowNode == null || windowNode.isNull()) {
            throw fail(raw, RuleFailureReason.MISSING_REQUIRED_FIELD,
                    "必填字段 'window' 缺失（毫秒数或 ISO-8601 时长，如 60000 / 'PT1M'）");
        }
        try {
            if (windowNode.isNumber()) {
                long ms = windowNode.longValue();
                if (ms <= 0) {
                    throw fail(raw, RuleFailureReason.INVALID_VALUE,
                            "window 必须为正数毫秒，实际: " + ms);
                }
                return Duration.ofMillis(ms);
            }
            if (windowNode.isTextual()) {
                Duration d = Duration.parse(windowNode.asText());
                if (d.isZero() || d.isNegative()) {
                    throw fail(raw, RuleFailureReason.INVALID_VALUE,
                            "window 必须为正时长，实际: " + windowNode.asText());
                }
                return d;
            }
        } catch (DateTimeParseException e) {
            throw fail(raw, RuleFailureReason.SYNTAX_ERROR,
                    "window 不是合法的 ISO-8601 时长: '" + windowNode.asText() + "' (" + e.getMessage() + ")");
        }
        throw fail(raw, RuleFailureReason.SYNTAX_ERROR,
                "window 必须是毫秒数或 ISO-8601 时长字符串");
    }

    /** filter 可省略（匹配全部事件），为单个条件对象，或含 and 数组的对象。 */
    private Condition parseFilter(JsonNode filterNode) {
        if (filterNode == null || filterNode.isNull()) {
            return new AndCondition(List.of());
        }
        if (!filterNode.isObject()) {
            throw new RuleValidationException(new RuleFailure(null, -1,
                    RuleFailureReason.SYNTAX_ERROR, "filter 必须是条件对象"));
        }
        if (filterNode.has("and")) {
            JsonNode and = filterNode.get("and");
            if (!and.isArray()) {
                throw new RuleValidationException(new RuleFailure(null, -1,
                        RuleFailureReason.SYNTAX_ERROR, "filter.and 必须是数组"));
            }
            List<Condition> children = new ArrayList<>();
            for (JsonNode child : and) {
                children.add(parseLeaf(child));
            }
            return new AndCondition(children);
        }
        return parseLeaf(filterNode);
    }

    private Condition parseLeaf(JsonNode n) {
        if (n == null || !n.isObject()) {
            throw new RuleValidationException(new RuleFailure(null, -1,
                    RuleFailureReason.SYNTAX_ERROR, "条件必须是 JSON 对象"));
        }
        if (n.has("and")) {
            return parseFilter(n);
        }
        if (!n.hasNonNull("field") || !n.hasNonNull("op")) {
            throw new RuleValidationException(new RuleFailure(null, -1,
                    RuleFailureReason.MISSING_REQUIRED_FIELD,
                    "条件必须包含非空的 field 与 op"));
        }
        String field = n.get("field").asText();
        String opSymbol = n.get("op").asText();
        ComparisonOperator op = ComparisonOperator.fromJson(opSymbol)
                .orElseThrow(() -> new RuleValidationException(new RuleFailure(null, -1,
                        RuleFailureReason.SYNTAX_ERROR, "不支持的比较运算符: '" + opSymbol + "'")));
        Object value = convertValue(n.get("value"), field);
        return new LeafCondition(field, op, value);
    }

    private Object convertValue(JsonNode valueNode, String field) {
        if (valueNode == null || valueNode.isNull()) {
            return null;
        }
        if (valueNode.isArray()) {
            List<Object> list = new ArrayList<>();
            for (JsonNode item : valueNode) {
                list.add(convertScalar(item, field));
            }
            return list;
        }
        return convertScalar(valueNode, field);
    }

    private Object convertScalar(JsonNode n, String field) {
        if (n == null || n.isNull()) {
            return null;
        }
        if (schema.isInstantAttribute(field) && n.isTextual()) {
            return Instant.parse(n.asText());
        }
        if (n.isTextual()) {
            return n.asText();
        }
        if (n.isBoolean()) {
            return n.booleanValue();
        }
        if (n.isIntegralNumber()) {
            return n.longValue();
        }
        if (n.isNumber()) {
            return n.doubleValue();
        }
        throw new RuleValidationException(new RuleFailure(null, -1,
                RuleFailureReason.SYNTAX_ERROR,
                "不支持的条件值类型: " + n.getNodeType()));
    }

    private RuleValidationException fail(RawRule raw, RuleFailureReason reason, String detail) {
        return new RuleValidationException(new RuleFailure(raw.idHint(), raw.index(), reason, detail));
    }
}
