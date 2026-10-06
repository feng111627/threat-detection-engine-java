package com.github.feng111627.threatdetectionenginejava.rule;

import java.util.List;

/**
 * 规则集注册表：原子持有当前生效的不可变 {@link RuleSet} 快照。
 *
 * <p>更新采用整集替换（snapshot swap）：先把新规则完整校验、收集到一个不可变列表，
 * 再一次性发布。评估方读取单个 {@code volatile} 引用，因此一次评估要么看到整个旧集，
 * 要么看到整个新集，绝不会看到只加载了一半的规则集。
 */
public final class RuleRegistry {

    private volatile RuleSet current = RuleSet.EMPTY;
    private long nextVersion = 1;

    public RuleSet current() {
        return current;
    }

    /**
     * 用已完整校验的规则列表整体替换当前规则集。
     * 调用方必须保证 rules 已校验通过；替换动作本身是原子的。
     */
    public synchronized RuleSet replace(List<CompiledRule> rules) {
        RuleSet next = new RuleSet(nextVersion++, List.copyOf(rules));
        current = next;
        return next;
    }
}
