package com.github.feng111627.threatdetectionenginejava.engine;

import java.util.List;

/** 单个事件的评估结果。 */
public record EvaluationResult(String eventId, List<Alert> newAlerts, int duplicateDroppedCount,
                               long rulesetVersion) {

    public EvaluationResult {
        newAlerts = List.copyOf(newAlerts);
    }

    public int alertCount() {
        return newAlerts.size();
    }
}
