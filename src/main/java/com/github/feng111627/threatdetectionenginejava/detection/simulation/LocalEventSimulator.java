package com.github.feng111627.threatdetectionenginejava.detection.simulation;

import com.github.feng111627.threatdetectionenginejava.detection.engine.DetectionService;
import com.github.feng111627.threatdetectionenginejava.detection.model.Alert;
import com.github.feng111627.threatdetectionenginejava.detection.model.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * 本地事件模拟器：启动后构造本地事件数据，
 * 演示规则加载、事件时间窗口状态关联（含乱序/重复投递）与规则热更新。
 */
@Component
public class LocalEventSimulator implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(LocalEventSimulator.class);
    private static final long T0 = 1_700_000_000_000L;

    private final DetectionService service;

    public LocalEventSimulator(DetectionService service) {
        this.service = service;
    }

    @Override
    public void run(String... args) {
        log.info("==== 本地威胁检测模拟开始 ====");

        // 1. 加载规则：5 分钟内同一 sourceIp 出现 >=3 次失败登录即告警
        String rulesJson = """
                [
                  {
                    "id": "brute-force-login",
                    "description": "同一来源 IP 5 分钟内 3 次登录失败",
                    "eventType": "login",
                    "entityField": "sourceIp",
                    "field": "status",
                    "op": "EQ",
                    "value": "failure",
                    "threshold": 3,
                    "windowMillis": 300000
                  }
                ]
                """;
        var loadResult = service.reloadRules(rulesJson);
        log.info("规则加载: 成功 {} 条, 失败 {} 条", loadResult.rules().size(), loadResult.errors().size());

        // 2. 构造本地事件：乱序到达 + 一次重复投递
        String ip = "10.0.0.7";
        List<SecurityEvent> events = List.of(
                login("e2", ip, T0 + 2_000),
                login("e1", ip, T0 + 1_000),   // 乱序：e1 比 e2 晚到
                login("e2", ip, T0 + 2_000),   // 重复投递：不应影响计数
                login("e3", ip, T0 + 3_000));  // 凑满阈值 -> 告警
        for (SecurityEvent e : events) {
            List<Alert> fired = service.ingest(e);
            log.info("事件 {} 摄入, 本次告警 {} 条", e.eventId(), fired.size());
        }

        // 3. 窗口外的新 episode：6 分钟后又一批失败登录 -> 新告警
        long t2 = T0 + 400_000;
        for (int i = 1; i <= 3; i++) {
            service.ingest(login("f" + i, ip, t2 + i * 1_000));
        }
        log.info("模拟结束, 累计告警 {} 条: {}", service.alerts().size(),
                service.alerts().stream().map(Alert::fingerprint).toList());
        log.info("==== 本地威胁检测模拟结束 ====");
    }

    private SecurityEvent login(String id, String ip, long ts) {
        return new SecurityEvent(id, "login", ts,
                Map.of("sourceIp", ip, "user", "alice", "status", "failure"));
    }
}
