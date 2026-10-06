package com.github.feng111627.threatdetectionenginejava.rule;

import java.util.List;

/**
 * 严格热更新被整体拒绝：新规则集中存在非法规则。
 * 此时原规则集保持不变（绝不发布半成品），失败明细随异常返回。
 */
public class RuleReloadRejectedException extends RuntimeException {

    private final transient RuleLoadReport report;

    public RuleReloadRejectedException(RuleLoadReport report) {
        super("规则热更新被拒绝: " + report.failureCount() + " 条规则非法，已保留原规则集(version 不变)。失败明细: "
                + report.failures().stream().map(Object::toString).toList());
        this.report = report;
    }

    public RuleLoadReport getReport() {
        return report;
    }

    public List<RuleFailure> getFailures() {
        return report.failures();
    }
}
