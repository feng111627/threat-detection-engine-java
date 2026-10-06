package com.github.feng111627.threatdetectionenginejava.tests.support;

import org.junit.jupiter.api.Assertions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.BooleanSupplier;

/**
 * 测试场景日志辅助：统一输出 场景 / 用例 / 期望 / 实际 / 结论，
 * 让测试运行日志能直观看出覆盖了哪些场景及其结果。
 */
public final class TestLogs {

    private TestLogs() {
    }

    public static void group(Class<?> owner, String group) {
        Logger log = LoggerFactory.getLogger(owner);
        log.info("");
        log.info("==================== 场景组: {} ====================", group);
    }

    public static void caseStart(Class<?> owner, String scenario, String detail) {
        Logger log = LoggerFactory.getLogger(owner);
        log.info("[场景] {} | 用例: {}", scenario, detail);
    }

    public static void expect(Class<?> owner, String expectation) {
        Logger log = LoggerFactory.getLogger(owner);
        log.info("        期望: {}", expectation);
    }

    public static void actual(Class<?> owner, String actual) {
        Logger log = LoggerFactory.getLogger(owner);
        log.info("        实际: {}", actual);
    }

    public static void check(Class<?> owner, String name, boolean condition) {
        Logger log = LoggerFactory.getLogger(owner);
        if (condition) {
            log.info("        断言[{}] => 通过 PASS", name);
        } else {
            log.info("        断言[{}] => 失败 FAIL", name);
        }
        Assertions.assertTrue(condition, name);
    }

    public static void check(Class<?> owner, String name, BooleanSupplier condition) {
        check(owner, name, condition.getAsBoolean());
    }
}
