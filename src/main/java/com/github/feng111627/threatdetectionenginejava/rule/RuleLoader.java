package com.github.feng111627.threatdetectionenginejava.rule;

import com.github.feng111627.threatdetectionenginejava.model.EventSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 规则加载器：解析 + 逐条校验编译。
 *
 * <p>关键保证：一条坏规则不会连累其他规则。每条规则独立处理，合法的进入
 * {@link RuleLoadReport#loaded()}，坏的进入 {@link RuleLoadReport#failures()}
 * 并带可区分的 {@link RuleFailureReason}。
 */
public final class RuleLoader {

    private static final Logger log = LoggerFactory.getLogger(RuleLoader.class);

    private final RuleParser parser;
    private final RuleValidator validator;

    public RuleLoader() {
        this(new RuleParser(), new RuleValidator(EventSchema.defaultSchema()));
    }

    public RuleLoader(RuleParser parser, RuleValidator validator) {
        this.parser = parser;
        this.validator = validator;
    }

    /** 容错加载：合法规则进 loaded，坏规则进 failures，逐条独立处理。 */
    public RuleLoadReport loadTolerant(String json) {
        List<RawRule> rawRules;
        try {
            rawRules = parser.parse(json);
        } catch (RuleParseException e) {
            // 文件级错误：无法拆分单条规则，整体计为一条失败
            RuleFailure failure = new RuleFailure(null, -1, RuleFailureReason.SYNTAX_ERROR, e.getMessage());
            log.warn("规则文件解析失败: {}", e.getMessage());
            return new RuleLoadReport(0, List.of(), List.of(failure));
        }

        List<CompiledRule> loaded = new ArrayList<>();
        List<RuleFailure> failures = new ArrayList<>();
        Set<String> seenIds = new HashSet<>();

        for (RawRule raw : rawRules) {
            try {
                CompiledRule rule = validator.validateAndCompile(raw);
                if (!seenIds.add(rule.getId())) {
                    RuleFailure dup = new RuleFailure(rule.getId(), raw.index(),
                            RuleFailureReason.DUPLICATE_RULE_ID,
                            "规则 id '" + rule.getId() + "' 在批次中重复");
                    failures.add(dup);
                    log.warn("跳过重复规则: {}", dup);
                    continue;
                }
                loaded.add(rule);
                log.debug("规则加载成功: id={} name={}", rule.getId(), rule.getName());
            } catch (RuleValidationException e) {
                failures.add(e.getFailure());
                log.warn("规则加载失败被隔离: {}", e.getFailure());
            }
        }

        RuleLoadReport report = new RuleLoadReport(rawRules.size(), loaded, failures);
        log.info("规则加载完成: 候选={}, 成功={}, 失败={}",
                report.totalCandidates(), report.loadedCount(), report.failureCount());
        return report;
    }
}
