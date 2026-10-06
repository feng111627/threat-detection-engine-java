package com.github.feng111627.threatdetectionenginejava.rule;

/** 条件自检发现的问题：带可区分的失败原因与人类可读细节。 */
public record ConditionIssue(RuleFailureReason reason, String detail) {

    @Override
    public String toString() {
        return reason + ": " + detail;
    }
}
