package com.github.feng111627.threatdetectionenginejava.detection.rule;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.threatdetectionenginejava.detection.rule.RuleFormatException.Reason;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 规则解析与校验。坏规则记录错误后继续解析后续规则，不让一条坏规则拖垮整批。
 */
public class RuleParser {

    /** 事件允许被规则引用的字段。 */
    public static final Set<String> KNOWN_FIELDS = Set.of(
            "eventId", "eventType", "sourceIp", "user", "host", "action", "status");

    private static final Set<String> REQUIRED_FIELDS = Set.of(
            "id", "eventType", "entityField", "field", "op", "value", "threshold", "windowMillis");

    private final ObjectMapper mapper = new ObjectMapper();

    public RuleLoadResult parseAll(String json) {
        List<DetectionRule> rules = new ArrayList<>();
        List<RuleFormatException> errors = new ArrayList<>();

        JsonNode root;
        try {
            root = mapper.readTree(json);
        } catch (Exception e) {
            // 整体语法错误：整批无法解析
            errors.add(new RuleFormatException(Reason.SYNTAX_ERROR, null,
                    "规则集 JSON 语法错误: " + e.getMessage()));
            return new RuleLoadResult(rules, errors);
        }
        if (!root.isArray()) {
            errors.add(new RuleFormatException(Reason.SYNTAX_ERROR, null,
                    "规则集必须是 JSON 数组"));
            return new RuleLoadResult(rules, errors);
        }

        Set<String> seenIds = new HashSet<>();
        for (JsonNode node : root) {
            String id = node.path("id").isTextual() ? node.path("id").asText() : null;
            try {
                DetectionRule rule = parseOne(node, seenIds);
                rules.add(rule);
                seenIds.add(rule.id());
            } catch (RuleFormatException e) {
                errors.add(e);
            }
        }
        return new RuleLoadResult(List.copyOf(rules), List.copyOf(errors));
    }

    private DetectionRule parseOne(JsonNode node, Set<String> seenIds) throws RuleFormatException {
        String id = node.path("id").isTextual() ? node.path("id").asText() : null;

        // 必填字段缺失
        for (String required : REQUIRED_FIELDS) {
            if (!node.has(required) || node.get(required).isNull()) {
                throw new RuleFormatException(Reason.MISSING_FIELD, id,
                        "规则缺少必填字段: " + required);
            }
        }
        if (id == null || id.isBlank()) {
            throw new RuleFormatException(Reason.MISSING_FIELD, null, "规则 id 不能为空");
        }
        if (seenIds.contains(id)) {
            throw new RuleFormatException(Reason.DUPLICATE_ID, id, "规则 id 重复: " + id);
        }

        // 引用字段必须存在
        String entityField = node.path("entityField").asText();
        String field = node.path("field").asText();
        if (!KNOWN_FIELDS.contains(entityField)) {
            throw new RuleFormatException(Reason.UNKNOWN_FIELD, id,
                    "entityField 引用了不存在的字段: " + entityField);
        }
        if (!KNOWN_FIELDS.contains(field)) {
            throw new RuleFormatException(Reason.UNKNOWN_FIELD, id,
                    "field 引用了不存在的字段: " + field);
        }

        // 操作符合法
        DetectionRule.ConditionOp op;
        try {
            op = DetectionRule.ConditionOp.valueOf(node.path("op").asText());
        } catch (IllegalArgumentException e) {
            throw new RuleFormatException(Reason.INVALID_VALUE, id,
                    "不支持的 op: " + node.path("op").asText());
        }

        // 数值合法
        JsonNode thresholdNode = node.path("threshold");
        JsonNode windowNode = node.path("windowMillis");
        if (!thresholdNode.isInt() || thresholdNode.asInt() <= 0) {
            throw new RuleFormatException(Reason.INVALID_VALUE, id,
                    "threshold 必须是正整数: " + thresholdNode);
        }
        if (!windowNode.isLong() && !windowNode.isInt() || windowNode.asLong() <= 0) {
            throw new RuleFormatException(Reason.INVALID_VALUE, id,
                    "windowMillis 必须是正数: " + windowNode);
        }

        String description = node.path("description").isTextual()
                ? node.path("description").asText() : "";
        return new DetectionRule(
                id,
                description,
                node.path("eventType").asText(),
                entityField,
                field,
                op,
                node.path("value").asText(),
                thresholdNode.asInt(),
                windowNode.asLong());
    }
}
