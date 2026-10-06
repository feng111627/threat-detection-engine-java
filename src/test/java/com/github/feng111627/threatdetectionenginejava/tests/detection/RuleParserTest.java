package com.github.feng111627.threatdetectionenginejava.tests.detection;

import com.github.feng111627.threatdetectionenginejava.detection.rule.RuleFormatException.Reason;
import com.github.feng111627.threatdetectionenginejava.detection.rule.RuleLoadResult;
import com.github.feng111627.threatdetectionenginejava.detection.rule.RuleParser;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 场景：规则加载与校验。
 * 覆盖：合法规则、JSON 语法错误、必填字段缺失、引用不存在字段、
 * 非法取值、id 重复、坏规则不影响同批好规则。
 */
class RuleParserTest {

    private static final Logger log = LoggerFactory.getLogger(RuleParserTest.class);
    private final RuleParser parser = new RuleParser();

    private static final String VALID_RULE = """
            {
              "id": "r1",
              "description": "暴力破解",
              "eventType": "login",
              "entityField": "sourceIp",
              "field": "status",
              "op": "EQ",
              "value": "failure",
              "threshold": 3,
              "windowMillis": 300000
            }
            """;

    @Test
    void validRuleParses() {
        RuleLoadResult result = parser.parseAll("[" + VALID_RULE + "]");
        log.info("[用例] 合法规则 -> 成功 {} 条, 错误 {}", result.rules().size(), result.errors());
        assertEquals(1, result.rules().size());
        assertTrue(result.errors().isEmpty());
        assertEquals("r1", result.rules().get(0).id());
    }

    @Test
    void syntaxErrorIsReported() {
        RuleLoadResult result = parser.parseAll("[{not valid json");
        log.info("[用例] JSON 语法错误 -> 错误 {}", result.errors());
        assertEquals(1, result.errors().size());
        assertEquals(Reason.SYNTAX_ERROR, result.errors().get(0).reason());
    }

    @Test
    void missingRequiredFieldIsReported() {
        String noThreshold = VALID_RULE.replace("\"threshold\": 3,", "");
        RuleLoadResult result = parser.parseAll("[" + noThreshold + "]");
        log.info("[用例] 缺少 threshold -> 错误 {}", result.errors());
        assertEquals(1, result.errors().size());
        assertEquals(Reason.MISSING_FIELD, result.errors().get(0).reason());
    }

    @Test
    void unknownFieldIsReported() {
        String badField = VALID_RULE.replace("\"field\": \"status\"", "\"field\": \"noSuchField\"");
        RuleLoadResult result = parser.parseAll("[" + badField + "]");
        log.info("[用例] 引用不存在字段 -> 错误 {}", result.errors());
        assertEquals(1, result.errors().size());
        assertEquals(Reason.UNKNOWN_FIELD, result.errors().get(0).reason());
    }

    @Test
    void invalidValueIsReported() {
        String badThreshold = VALID_RULE.replace("\"threshold\": 3", "\"threshold\": 0");
        RuleLoadResult result = parser.parseAll("[" + badThreshold + "]");
        log.info("[用例] threshold=0 -> 错误 {}", result.errors());
        assertEquals(1, result.errors().size());
        assertEquals(Reason.INVALID_VALUE, result.errors().get(0).reason());
    }

    @Test
    void duplicateIdIsReported() {
        RuleLoadResult result = parser.parseAll("[" + VALID_RULE + "," + VALID_RULE + "]");
        log.info("[用例] id 重复 -> 错误 {}", result.errors());
        assertEquals(1, result.rules().size());
        assertEquals(1, result.errors().size());
        assertEquals(Reason.DUPLICATE_ID, result.errors().get(0).reason());
    }

    @Test
    void badRuleDoesNotKillBatch() {
        String bad = VALID_RULE.replace("\"field\": \"status\"", "\"field\": \"ghost\"")
                .replace("\"id\": \"r1\"", "\"id\": \"r2\"");
        RuleLoadResult result = parser.parseAll("[" + bad + "," + VALID_RULE + "]");
        log.info("[用例] 一坏一好 -> 成功 {} 条, 错误 {}", result.rules().size(), result.errors());
        assertEquals(1, result.rules().size());
        assertEquals("r1", result.rules().get(0).id());
        assertEquals(1, result.errors().size());
        assertEquals(Reason.UNKNOWN_FIELD, result.errors().get(0).reason());
    }
}
