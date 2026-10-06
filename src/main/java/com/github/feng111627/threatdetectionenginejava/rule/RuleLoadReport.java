package com.github.feng111627.threatdetectionenginejava.rule;

import java.util.List;

/** 一批规则的加载结果报告（成功的规则 + 每条坏规则的独立失败原因）。 */
public record RuleLoadReport(int totalCandidates, List<CompiledRule> loaded, List<RuleFailure> failures) {

    public RuleLoadReport {
        loaded = List.copyOf(loaded);
        failures = List.copyOf(failures);
    }

    public int loadedCount() {
        return loaded.size();
    }

    public int failureCount() {
        return failures.size();
    }

    public boolean hasFailures() {
        return !failures.isEmpty();
    }
}
