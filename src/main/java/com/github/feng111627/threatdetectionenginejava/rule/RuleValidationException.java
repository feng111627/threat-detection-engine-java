package com.github.feng111627.threatdetectionenginejava.rule;

/** 单条规则校验失败时抛出，携带可区分的失败原因。 */
public class RuleValidationException extends RuntimeException {

    private final RuleFailure failure;

    public RuleValidationException(RuleFailure failure) {
        super(failure.toString());
        this.failure = failure;
    }

    public RuleValidationException(RuleFailure failure, Throwable cause) {
        super(failure.toString(), cause);
        this.failure = failure;
    }

    public RuleFailure getFailure() {
        return failure;
    }
}
