package com.github.feng111627.threatdetectionenginejava.rule;

import com.github.feng111627.threatdetectionenginejava.model.EventSchema;
import com.github.feng111627.threatdetectionenginejava.model.SecurityEvent;
import java.util.ArrayList;
import java.util.List;

/** 组合条件：所有子条件同时满足。 */
public final class AndCondition implements Condition {

    private final List<Condition> children;

    public AndCondition(List<Condition> children) {
        this.children = List.copyOf(children);
    }

    public List<Condition> getChildren() {
        return children;
    }

    @Override
    public boolean matches(SecurityEvent event) {
        for (Condition child : children) {
            if (!child.matches(event)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public List<ConditionIssue> validate(EventSchema schema) {
        List<ConditionIssue> issues = new ArrayList<>();
        for (Condition child : children) {
            issues.addAll(child.validate(schema));
        }
        return issues;
    }
}
