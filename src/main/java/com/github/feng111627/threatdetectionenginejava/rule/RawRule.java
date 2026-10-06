package com.github.feng111627.threatdetectionenginejava.rule;

import com.fasterxml.jackson.databind.JsonNode;

/** 解析后的规则原始 JSON 节点及位置信息。 */
public record RawRule(String idHint, int index, JsonNode node) {
}
