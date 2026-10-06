package com.github.feng111627.threatdetectionenginejava.detection.engine;

import com.github.feng111627.threatdetectionenginejava.detection.model.Alert;
import com.github.feng111627.threatdetectionenginejava.detection.model.SecurityEvent;
import com.github.feng111627.threatdetectionenginejava.detection.rule.DetectionRule;
import com.github.feng111627.threatdetectionenginejava.detection.rule.RuleLoadResult;
import com.github.feng111627.threatdetectionenginejava.detection.rule.RuleRegistry;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 对外门面：事件摄入 + 规则热更新 + 告警查询。
 * 摄入时先取规则集快照再评估，热更新对进行中的评估无影响。
 */
@Service
public class DetectionService {

    private final RuleRegistry registry = new RuleRegistry();
    private final DetectionEngine engine = new DetectionEngine();
    private final CopyOnWriteArrayList<Alert> alerts = new CopyOnWriteArrayList<>();

    public List<Alert> ingest(SecurityEvent event) {
        List<DetectionRule> snapshot = registry.currentRules();
        List<Alert> fired = engine.evaluate(event, snapshot);
        alerts.addAll(fired);
        return fired;
    }

    public RuleLoadResult reloadRules(String json) {
        return registry.reload(json);
    }

    public List<DetectionRule> currentRules() {
        return registry.currentRules();
    }

    public List<Alert> alerts() {
        return List.copyOf(alerts);
    }
}
