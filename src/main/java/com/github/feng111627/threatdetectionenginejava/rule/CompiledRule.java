package com.github.feng111627.threatdetectionenginejava.rule;

import java.time.Duration;

/** 一条已校验、可执行的检测规则（不可变）。 */
public final class CompiledRule {

    private final String id;
    private final String name;
    private final String description;
    private final String entityField;
    private final int threshold;
    private final Duration window;
    private final Condition filter;

    public CompiledRule(String id, String name, String description, String entityField,
                        int threshold, Duration window, Condition filter) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.entityField = entityField;
        this.threshold = threshold;
        this.window = window;
        this.filter = filter;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public String getEntityField() { return entityField; }
    public int getThreshold() { return threshold; }
    public Duration getWindow() { return window; }
    public Condition getFilter() { return filter; }
}
