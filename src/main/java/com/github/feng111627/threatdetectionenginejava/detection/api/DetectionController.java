package com.github.feng111627.threatdetectionenginejava.detection.api;

import com.github.feng111627.threatdetectionenginejava.detection.engine.DetectionService;
import com.github.feng111627.threatdetectionenginejava.detection.model.Alert;
import com.github.feng111627.threatdetectionenginejava.detection.model.SecurityEvent;
import com.github.feng111627.threatdetectionenginejava.detection.rule.DetectionRule;
import com.github.feng111627.threatdetectionenginejava.detection.rule.RuleLoadResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * REST 接口：事件摄入、规则热更新、告警查询。
 */
@RestController
@RequestMapping("/api/detection")
public class DetectionController {

    private final DetectionService service;

    public DetectionController(DetectionService service) {
        this.service = service;
    }

    /** 摄入一条事件，返回本次触发的告警。 */
    @PostMapping("/events")
    public List<Alert> ingest(@RequestBody SecurityEvent event) {
        return service.ingest(event);
    }

    /**
     * 热更新规则集。全部规则合法才原子替换；
     * 存在坏规则时返回 400 与失败明细，原规则集保持不变。
     */
    @PostMapping(value = "/rules/reload", consumes = "application/json")
    public ResponseEntity<?> reload(@RequestBody String rulesJson) {
        RuleLoadResult result = service.reloadRules(rulesJson);
        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "rejected",
                    "errors", result.errors().stream().map(e -> Map.of(
                            "reason", e.reason().name(),
                            "ruleId", e.ruleId() == null ? "" : e.ruleId(),
                            "message", e.getMessage())).toList()));
        }
        return ResponseEntity.ok(Map.of(
                "status", "reloaded",
                "ruleCount", result.rules().size()));
    }

    @GetMapping("/rules")
    public List<DetectionRule> rules() {
        return service.currentRules();
    }

    @GetMapping("/alerts")
    public List<Alert> alerts() {
        return service.alerts();
    }
}
