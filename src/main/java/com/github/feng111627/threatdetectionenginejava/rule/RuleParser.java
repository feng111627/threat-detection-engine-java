package com.github.feng111627.threatdetectionenginejava.rule;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

/**
 * 把规则定义文本解析为 {@link RawRule} 列表。
 *
 * <p>本类只负责 JSON 层面的解析：文件必须是合法 JSON，且顶层为规则数组
 * （或包含 {@code rules} 数组的对象）。单条规则的结构与语义错误不在此处理，
 * 而由 {@link RuleValidator} 逐条给出可区分的失败原因。
 */
public final class RuleParser {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<RawRule> parse(String json) {
        if (json == null || json.isBlank()) {
            throw new RuleParseException("规则内容为空");
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(json);
        } catch (Exception e) {
            throw new RuleParseException("规则文件不是合法 JSON: " + e.getMessage(), e);
        }
        JsonNode array = root;
        if (root.isObject() && root.has("rules")) {
            array = root.get("rules");
        }
        if (array == null || !array.isArray()) {
            throw new RuleParseException("规则文件顶层必须是规则数组（或含 rules 数组的对象）");
        }
        List<RawRule> rawRules = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            JsonNode node = array.get(i);
            String hint = node != null && node.isObject() && node.hasNonNull("id")
                    ? node.get("id").asText() : null;
            rawRules.add(new RawRule(hint, i, node));
        }
        return rawRules;
    }
}
