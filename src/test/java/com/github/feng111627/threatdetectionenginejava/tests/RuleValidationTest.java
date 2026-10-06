package com.github.feng111627.threatdetectionenginejava.tests;

import com.github.feng111627.threatdetectionenginejava.rule.RuleFailureReason;
import com.github.feng111627.threatdetectionenginejava.rule.RuleLoadReport;
import com.github.feng111627.threatdetectionenginejava.rule.RuleLoader;
import com.github.feng111627.threatdetectionenginejava.tests.support.TestLogs;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则加载与校验主流程 / 关键边界测试。
 * 日志逐条打印 场景、用例、期望、实际与断言结论。
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RuleValidationTest {

    private static final Class<?> ME = RuleValidationTest.class;
    private final RuleLoader loader = new RuleLoader();

    private static final String GOOD_RULE = """
            {
              "id": "GOOD-1",
              "name": "登录失败",
              "entityField": "entityId",
              "threshold": 3,
              "window": "PT1M",
              "filter": {
                "and": [
                  { "field": "eventType", "op": "==", "value": "LOGIN" },
                  { "field": "attr.outcome", "op": "==", "value": "FAILURE" }
                ]
              }
            }
            """;

    private RuleLoadReport loadOne(String badRuleJson) {
        String batch = "[" + GOOD_RULE + "," + badRuleJson + "]";
        return loader.loadTolerant(batch);
    }

    private void assertSingleFailure(RuleLoadReport report, RuleFailureReason reason, String keyword) {
        TestLogs.actual(ME, "成功规则数=" + report.loadedCount() + ", 失败规则数=" + report.failureCount()
                + ", 失败明细=" + report.failures());
        TestLogs.check(ME, "好规则不受坏规则连累(loaded=1)", report.loadedCount() == 1);
        TestLogs.check(ME, "恰好 1 条坏规则(failures=1)", report.failureCount() == 1);
        TestLogs.check(ME, "失败原因分类为 " + reason,
                report.failures().get(0).reason() == reason);
        TestLogs.check(ME, "失败细节包含关键字 '" + keyword + "'",
                report.failures().get(0).detail().contains(keyword));
    }

    @Test
    @Order(1)
    void case01_syntaxError_notJson() {
        TestLogs.group(ME, "规则校验");
        TestLogs.caseStart(ME, "语法错误-SYNTAX_ERROR", "整个文件不是合法 JSON");
        TestLogs.expect(ME, "整体 1 条失败，原因 SYNTAX_ERROR，loaded=0");
        RuleLoadReport report = loader.loadTolerant("{ this is : not-json ]");
        TestLogs.actual(ME, "失败明细=" + report.failures());
        TestLogs.check(ME, "loaded=0", report.loadedCount() == 0);
        TestLogs.check(ME, "原因=SYNTAX_ERROR",
                report.failures().get(0).reason() == RuleFailureReason.SYNTAX_ERROR);
    }

    @Test
    @Order(2)
    void case02_syntaxError_badWindow() {
        TestLogs.caseStart(ME, "语法错误-SYNTAX_ERROR", "window 是无法解析的时长字符串");
        TestLogs.expect(ME, "坏规则被隔离，原因 SYNTAX_ERROR，好规则照常加载");
        String bad = """
                { "id":"BAD-WINDOW","name":"x","entityField":"entityId",
                  "window":"not-a-duration",
                  "filter":{"field":"eventType","op":"==","value":"A"} }
                """;
        assertSingleFailure(loadOne(bad), RuleFailureReason.SYNTAX_ERROR, "window");
    }

    @Test
    @Order(3)
    void case03_syntaxError_unknownOperator() {
        TestLogs.caseStart(ME, "语法错误-SYNTAX_ERROR", "filter 使用了不支持的运算符 ~~");
        TestLogs.expect(ME, "坏规则被隔离，原因 SYNTAX_ERROR，细节指出运算符");
        String bad = """
                { "id":"BAD-OP","name":"x","entityField":"entityId","window":"PT1M",
                  "filter":{"field":"eventType","op":"~~","value":"A"} }
                """;
        assertSingleFailure(loadOne(bad), RuleFailureReason.SYNTAX_ERROR, "~~");
    }

    @Test
    @Order(4)
    void case04_missingRequiredField_id() {
        TestLogs.caseStart(ME, "必填缺失-MISSING_REQUIRED_FIELD", "规则缺少 id");
        TestLogs.expect(ME, "原因 MISSING_REQUIRED_FIELD，细节指出 id");
        String bad = """
                { "name":"x","entityField":"entityId","window":"PT1M",
                  "filter":{"field":"eventType","op":"==","value":"A"} }
                """;
        assertSingleFailure(loadOne(bad), RuleFailureReason.MISSING_REQUIRED_FIELD, "'id'");
    }

    @Test
    @Order(5)
    void case05_missingRequiredField_window() {
        TestLogs.caseStart(ME, "必填缺失-MISSING_REQUIRED_FIELD", "规则缺少 window");
        TestLogs.expect(ME, "原因 MISSING_REQUIRED_FIELD，细节指出 window");
        String bad = """
                { "id":"BAD-NO-WINDOW","name":"x","entityField":"entityId",
                  "filter":{"field":"eventType","op":"==","value":"A"} }
                """;
        assertSingleFailure(loadOne(bad), RuleFailureReason.MISSING_REQUIRED_FIELD, "'window'");
    }

    @Test
    @Order(6)
    void case06_unknownField_filter() {
        TestLogs.caseStart(ME, "未知字段-UNKNOWN_FIELD", "filter 引用不存在的字段 user.age");
        TestLogs.expect(ME, "原因 UNKNOWN_FIELD，细节指出字段名，不静默跳过");
        String bad = """
                { "id":"BAD-UNK","name":"x","entityField":"entityId","window":"PT1M",
                  "filter":{"field":"user.age","op":">","value":1} }
                """;
        assertSingleFailure(loadOne(bad), RuleFailureReason.UNKNOWN_FIELD, "user.age");
    }

    @Test
    @Order(7)
    void case07_unknownField_entityField() {
        TestLogs.caseStart(ME, "未知字段-UNKNOWN_FIELD", "entityField 引用不存在的字段 accountId");
        TestLogs.expect(ME, "原因 UNKNOWN_FIELD");
        String bad = """
                { "id":"BAD-ENT","name":"x","entityField":"accountId","window":"PT1M",
                  "filter":{"field":"eventType","op":"==","value":"A"} }
                """;
        assertSingleFailure(loadOne(bad), RuleFailureReason.UNKNOWN_FIELD, "accountId");
    }

    @Test
    @Order(8)
    void case08_typeMismatch() {
        TestLogs.caseStart(ME, "类型不符-TYPE_MISMATCH", "字符串字段 eventType 用 > 比较数字");
        TestLogs.expect(ME, "原因 TYPE_MISMATCH");
        String bad = """
                { "id":"BAD-TYPE","name":"x","entityField":"entityId","window":"PT1M",
                  "filter":{"field":"eventType","op":">","value":5} }
                """;
        assertSingleFailure(loadOne(bad), RuleFailureReason.TYPE_MISMATCH, "TYPE_MISMATCH");
    }

    @Test
    @Order(9)
    void case09_invalidValue_thresholdZero() {
        TestLogs.caseStart(ME, "非法值-INVALID_VALUE", "threshold = 0");
        TestLogs.expect(ME, "原因 INVALID_VALUE，细节指出 threshold");
        String bad = """
                { "id":"BAD-TH","name":"x","entityField":"entityId","threshold":0,"window":"PT1M",
                  "filter":{"field":"eventType","op":"==","value":"A"} }
                """;
        assertSingleFailure(loadOne(bad), RuleFailureReason.INVALID_VALUE, "threshold");
    }

    @Test
    @Order(10)
    void case10_invalidValue_negativeWindow() {
        TestLogs.caseStart(ME, "非法值-INVALID_VALUE", "window 为负数毫秒");
        TestLogs.expect(ME, "原因 INVALID_VALUE");
        String bad = """
                { "id":"BAD-NW","name":"x","entityField":"entityId","window":-1000,
                  "filter":{"field":"eventType","op":"==","value":"A"} }
                """;
        assertSingleFailure(loadOne(bad), RuleFailureReason.INVALID_VALUE, "window");
    }

    @Test
    @Order(11)
    void case11_duplicateRuleId() {
        TestLogs.caseStart(ME, "重复 ID-DUPLICATE_RULE_ID", "两条规则都用 id GOOD-1");
        TestLogs.expect(ME, "第二条被隔离，原因 DUPLICATE_RULE_ID，第一条保留");
        String dup = GOOD_RULE.replace("GOOD-1", "GOOD-1");
        RuleLoadReport report = loader.loadTolerant("[" + GOOD_RULE + "," + dup + "]");
        TestLogs.actual(ME, "成功=" + report.loadedCount() + " 失败=" + report.failureCount()
                + " 明细=" + report.failures());
        TestLogs.check(ME, "第一条保留(loaded=1)", report.loadedCount() == 1);
        TestLogs.check(ME, "重复 ID 被识别",
                report.failures().get(0).reason() == RuleFailureReason.DUPLICATE_RULE_ID);
    }

    @Test
    @Order(12)
    void case12_mixedBatch_isolation() {
        TestLogs.caseStart(ME, "混合批次-坏规则不连累整批",
                "3 条规则：1 好 + 1 未知字段 + 1 缺 id");
        TestLogs.expect(ME, "loaded=1, failures=2，且两条失败原因可区分");
        String unknown = """
                { "id":"BAD-A","name":"x","entityField":"entityId","window":"PT1M",
                  "filter":{"field":"nope","op":"==","value":"A"} }
                """;
        String missingId = """
                { "name":"no-id","entityField":"entityId","window":"PT1M",
                  "filter":{"field":"eventType","op":"==","value":"A"} }
                """;
        RuleLoadReport report = loader.loadTolerant("[" + GOOD_RULE + "," + unknown + "," + missingId + "]");
        TestLogs.actual(ME, report.failures().toString());
        TestLogs.check(ME, "loaded=1", report.loadedCount() == 1);
        TestLogs.check(ME, "failures=2", report.failureCount() == 2);
        boolean distinctReasons = report.failures().stream()
                .map(f -> f.reason()).distinct().count() == 2;
        TestLogs.check(ME, "两类失败原因彼此可区分", distinctReasons);
        assertTrue(report.failures().stream().anyMatch(f -> f.reason() == RuleFailureReason.UNKNOWN_FIELD));
        assertTrue(report.failures().stream().anyMatch(f -> f.reason() == RuleFailureReason.MISSING_REQUIRED_FIELD));
        assertEquals(3, report.totalCandidates());
    }
}
