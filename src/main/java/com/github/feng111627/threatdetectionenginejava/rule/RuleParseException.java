package com.github.feng111627.threatdetectionenginejava.rule;

/** 规则 JSON 无法解析为规则结构时抛出（语法错误）。 */
public class RuleParseException extends RuntimeException {
    public RuleParseException(String message) {
        super(message);
    }

    public RuleParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
