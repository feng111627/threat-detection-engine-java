package com.github.feng111627.threatdetectionenginejava.bootstrap;

import com.github.feng111627.threatdetectionenginejava.rule.RuleLoadReport;
import com.github.feng111627.threatdetectionenginejava.service.DetectionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * 启动时从 classpath:rules/sample-rules.json 加载默认规则集（容错方式）。
 * 加载后可随时通过 HTTP 热更新覆盖。
 */
@Component
public final class DefaultRuleBootstrap implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DefaultRuleBootstrap.class);
    private static final String DEFAULT_RULES = "rules/sample-rules.json";

    private final DetectionService service;

    public DefaultRuleBootstrap(DetectionService service) {
        this.service = service;
    }

    @Override
    public void run(String... args) {
        try {
            ClassPathResource resource = new ClassPathResource(DEFAULT_RULES);
            if (!resource.exists()) {
                log.info("未找到默认规则文件 {}，从空规则集启动", DEFAULT_RULES);
                return;
            }
            String json = resource.getContentAsString(StandardCharsets.UTF_8);
            RuleLoadReport report = service.reloadTolerant(json);
            log.info("默认规则加载完毕: 成功={} 失败={} 当前版本={}",
                    report.loadedCount(), report.failureCount(),
                    service.currentRuleset().getVersion());
        } catch (Exception e) {
            log.error("默认规则加载异常，以空规则集继续启动: {}", e.getMessage(), e);
        }
    }
}
