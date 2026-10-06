package com.github.feng111627.threatdetectionenginejava.web;

import com.github.feng111627.threatdetectionenginejava.engine.EvaluationResult;
import com.github.feng111627.threatdetectionenginejava.model.SecurityEvent;
import com.github.feng111627.threatdetectionenginejava.rule.CompiledRule;
import com.github.feng111627.threatdetectionenginejava.rule.RuleLoadReport;
import com.github.feng111627.threatdetectionenginejava.rule.RuleReloadRejectedException;
import com.github.feng111627.threatdetectionenginejava.rule.RuleSet;
import com.github.feng111627.threatdetectionenginejava.service.DetectionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** HTTP 接口：查看规则版本、热更新规则（容错/严格）、提交事件评估。 */
@RestController
@RequestMapping("/api/detection")
public final class DetectionController {

    private final DetectionService service;

    public DetectionController(DetectionService service) {
        this.service = service;
    }

    /** 查看当前生效规则集快照（版本 + 规则概要）。 */
    @GetMapping("/rules")
    public Map<String, Object> rules() {
        RuleSet rs = service.currentRuleset();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("version", rs.getVersion());
        body.put("ruleCount", rs.getRules().size());
        body.put("rules", rs.getRules().stream().map(this::ruleSummary).toList());
        return body;
    }

    /** 容错热更新：坏规则隔离，合法规则上线；报告中给出每条坏规则的原因。 */
    @PostMapping("/rules/reload")
    public Map<String, Object> reloadTolerant(@RequestBody String rulesJson) {
        RuleLoadReport report = service.reloadTolerant(rulesJson);
        return reportBody(report, service.currentRuleset().getVersion());
    }

    /** 严格热更新：任一规则非法则 400，原规则集保留。 */
    @PostMapping("/rules/reload-strict")
    public Map<String, Object> reloadStrict(@RequestBody String rulesJson) {
        RuleSet rs = service.reloadStrict(rulesJson);
        RuleLoadReport report = new RuleLoadReport(rs.getRules().size(), rs.getRules(), List.of());
        return reportBody(report, rs.getVersion());
    }

    /** 提交一个事件做检测评估。 */
    @PostMapping("/events")
    public Map<String, Object> evaluate(@RequestBody EventRequest request) {
        if (request.getEventTime() == null || request.getEventTime().isBlank()) {
            throw new IllegalArgumentException("eventTime 必填（ISO-8601，事件时间，窗口判定依据）");
        }
        SecurityEvent event = new SecurityEvent(
                request.getEventId(),
                request.getEventType(),
                request.getEntityId(),
                Instant.parse(request.getEventTime()),
                request.getAttributes());
        EvaluationResult result = service.evaluate(event);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("eventId", result.eventId());
        body.put("rulesetVersion", result.rulesetVersion());
        body.put("duplicateDropped", result.duplicateDroppedCount());
        body.put("newAlertCount", result.alertCount());
        body.put("newAlerts", result.newAlerts());
        return body;
    }

    @ExceptionHandler(RuleReloadRejectedException.class)
    public ResponseEntity<Map<String, Object>> handleRejected(RuleReloadRejectedException e) {
        Map<String, Object> body = reportBody(e.getReport(), service.currentRuleset().getVersion());
        body.put("rejected", true);
        body.put("message", "严格热更新失败，已保留原规则集");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }

    private Map<String, Object> ruleSummary(CompiledRule r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", r.getId());
        m.put("name", r.getName());
        m.put("entityField", r.getEntityField());
        m.put("threshold", r.getThreshold());
        m.put("windowMs", r.getWindow().toMillis());
        return m;
    }

    private Map<String, Object> reportBody(RuleLoadReport report, long activeVersion) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("activeVersion", activeVersion);
        body.put("totalCandidates", report.totalCandidates());
        body.put("loadedCount", report.loadedCount());
        body.put("failureCount", report.failureCount());
        body.put("failures", report.failures());
        return body;
    }
}
