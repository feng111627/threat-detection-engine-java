package com.github.feng111627.threatdetectionenginejava.detection.rule;

/**
 * 规则校验失败。reason 区分失败类别，便于调用方分别处理。
 */
public class RuleFormatException extends Exception {

    public enum Reason {
        SYNTAX_ERROR,      // JSON 语法错误
        MISSING_FIELD,     // 必填字段缺失
        UNKNOWN_FIELD,     // 引用了不存在的事件字段
        INVALID_VALUE,     // 字段取值非法（如 threshold<=0）
        DUPLICATE_ID       // 规则 id 重复
    }

    private final Reason reason;
    private final String ruleId;

    public RuleFormatException(Reason reason, String ruleId, String message) {
        super(message);
        this.reason = reason;
        this.ruleId = ruleId;
    }

    public Reason reason() {
        return reason;
    }

    public String ruleId() {
        return ruleId;
    }
}
