package com.github.feng111627.threatdetectionenginejava.detection.rule;

import java.util.List;

/**
 * 一批规则的加载结果：成功解析的规则 + 每条失败规则的错误明细。
 * 单条坏规则不影响其余规则加载。
 */
public record RuleLoadResult(
        List<DetectionRule> rules,
        List<RuleFormatException> errors) {

    public boolean hasErrors() {
        return !errors.isEmpty();
    }
}
