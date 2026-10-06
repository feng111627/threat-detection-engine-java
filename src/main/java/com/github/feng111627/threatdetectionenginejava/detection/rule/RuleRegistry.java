package com.github.feng111627.threatdetectionenginejava.detection.rule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 规则注册表。通过 AtomicReference 整体不可变替换：
 * 进行中的评估要么看到旧规则集，要么看到新规则集，绝不看到半更新状态。
 * 更新失败（存在坏规则）时保留原规则集并返回错误明细。
 */
public class RuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(RuleRegistry.class);

    private final RuleParser parser = new RuleParser();
    private final AtomicReference<List<DetectionRule>> rules = new AtomicReference<>(List.of());

    /** 当前生效的规则集快照（不可变）。 */
    public List<DetectionRule> currentRules() {
        return rules.get();
    }

    /**
     * 热更新规则集。全部规则解析成功才原子替换；任一规则失败则保留旧规则集。
     */
    public RuleLoadResult reload(String json) {
        RuleLoadResult result = parser.parseAll(json);
        if (result.hasErrors()) {
            log.warn("规则更新被拒绝，保留原规则集。失败明细: {}",
                    result.errors().stream()
                            .map(e -> e.reason() + "(" + e.ruleId() + "): " + e.getMessage())
                            .toList());
            return result;
        }
        List<DetectionRule> previous = rules.getAndSet(result.rules());
        log.info("规则集已原子替换: {} 条 -> {} 条", previous.size(), result.rules().size());
        return result;
    }
}
