package com.github.feng111627.threatdetectionenginejava.rule;

/** 规则加载/校验失败的可区分原因。 */
public enum RuleFailureReason {
    SYNTAX_ERROR,
    MISSING_REQUIRED_FIELD,
    UNKNOWN_FIELD,
    TYPE_MISMATCH,
    INVALID_VALUE,
    DUPLICATE_RULE_ID
}
