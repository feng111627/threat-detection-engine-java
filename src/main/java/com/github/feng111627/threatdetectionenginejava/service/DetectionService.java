package com.github.feng111627.threatdetectionenginejava.service;

import com.github.feng111627.threatdetectionenginejava.engine.DetectionEngine;
import com.github.feng111627.threatdetectionenginejava.engine.EvaluationResult;
import com.github.feng111627.threatdetectionenginejava.model.EventSchema;
import com.github.feng111627.threatdetectionenginejava.model.SecurityEvent;
import com.github.feng111627.threatdetectionenginejava.rule.CompiledRule;
import com.github.feng111627.threatdetectionenginejava.rule.RuleLoadReport;
import com.github.feng111627.threatdetectionenginejava.rule.RuleLoader;
import com.github.feng111627.threatdetectionenginejava.rule.RuleParser;
import com.github.feng111627.threatdetectionenginejava.rule.RuleRegistry;
import com.github.feng111627.threatdetectionenginejava.rule.RuleReloadRejectedException;
import com.github.feng111627.threatdetectionenginejava.rule.RuleSet;
import com.github.feng111627.threatdetectionenginejava.rule.RuleValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 门面服务：组合规则加载、热更新与事件评估。
 *
 * <p>两种热更新语义：
 * <ul>
 *   <li>{@link #reloadTolerant(String)}：坏规则被隔离，其余合法规则整集替换发布；</li>
 *   <li>{@link #reloadStrict(String)}：任一规则非法则整体拒绝，保留原规则集并抛出
 *       {@link RuleReloadRejectedException}。</li>
 * </ul>
 * 两种方式都在“全部规则校验完成之后”才做单次原子替换，因此评估方永远不会看到半集。
 */
public final class DetectionService {

    private static final Logger log = LoggerFactory.getLogger(DetectionService.class);

    private final RuleRegistry registry;
    private final RuleLoader loader;
    private final DetectionEngine engine;

    public DetectionService() {
        this(EventSchema.defaultSchema());
    }

    public DetectionService(EventSchema schema) {
        this.registry = new RuleRegistry();
        this.loader = new RuleLoader(new RuleParser(), new RuleValidator(schema));
        this.engine = new DetectionEngine(registry);
    }

    public RuleRegistry getRegistry() {
        return registry;
    }

    public DetectionEngine getEngine() {
        return engine;
    }

    public RuleSet currentRuleset() {
        return registry.current();
    }

    /** 容错热更新：隔离坏规则后，用全部合法规则整集替换；返回加载报告。 */
    public RuleLoadReport reloadTolerant(String rulesJson) {
        RuleSet before = registry.current();
        RuleLoadReport report = loader.loadTolerant(rulesJson);
        // 即便有失败，合法规则已经完整收集；replace 是单次原子发布
        RuleSet after = registry.replace(report.loaded());
        log.info("容错热更新完成 version {} -> {}, 上线规则={}, 隔离坏规则={}",
                before.getVersion(), after.getVersion(), report.loadedCount(), report.failureCount());
        return report;
    }

    /** 严格热更新：任一规则非法则整体拒绝，保留原规则集并抛出异常。 */
    public RuleSet reloadStrict(String rulesJson) {
        RuleSet before = registry.current();
        RuleLoadReport report = loader.loadTolerant(rulesJson);
        if (report.hasFailures()) {
            // 关键：不触碰 registry，原规则集（版本、内容）原样保留
            log.warn("严格热更新被拒绝，保留原规则集 version={}, 失败={}",
                    before.getVersion(), report.failures());
            throw new RuleReloadRejectedException(report);
        }
        RuleSet after = registry.replace(report.loaded());
        log.info("严格热更新成功 version {} -> {}, 上线规则={}",
                before.getVersion(), after.getVersion(), report.loadedCount());
        return after;
    }

    public EvaluationResult evaluate(SecurityEvent event) {
        return engine.evaluate(event);
    }

    /** 重置引擎关联状态（不清规则）。 */
    public void resetState() {
        engine.resetState();
    }

    /** 规则与状态全部重置（测试用）。 */
    public void reset() {
        registry.replace(java.util.List.<CompiledRule>of());
        engine.resetState();
    }
}
