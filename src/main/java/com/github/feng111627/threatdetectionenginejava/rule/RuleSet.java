package com.github.feng111627.threatdetectionenginejava.rule;

import java.util.List;

/** 某个时刻生效的不可变规则集快照。 */
public final class RuleSet {

    public static final RuleSet EMPTY = new RuleSet(0, List.of());

    private final long version;
    private final List<CompiledRule> rules;

    public RuleSet(long version, List<CompiledRule> rules) {
        this.version = version;
        this.rules = List.copyOf(rules);
    }

    public long getVersion() { return version; }
    public List<CompiledRule> getRules() { return rules; }
}
