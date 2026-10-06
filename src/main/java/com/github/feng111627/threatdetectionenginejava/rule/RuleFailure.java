package com.github.feng111627.threatdetectionenginejava.rule;

/** 单条规则的加载失败信息（可解释）。 */
public record RuleFailure(String ruleIdHint, int index, RuleFailureReason reason, String detail) {

    @Override
    public String toString() {
        return "[%s] index=%d hint=%s detail=%s".formatted(reason, index, ruleIdHint, detail);
    }
}
