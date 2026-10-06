package com.github.feng111627.threatdetectionenginejava.rule;

import java.util.Arrays;
import java.util.Optional;

/** 叶子条件支持的比较运算符（JSON 语法）。 */
public enum ComparisonOperator {
    EQ("=="),
    NE("!="),
    GT(">"),
    GTE(">="),
    LT("<"),
    LTE("<="),
    CONTAINS("contains"),
    STARTS_WITH("startsWith"),
    ENDS_WITH("endsWith"),
    IN("in");

    private final String jsonSymbol;

    ComparisonOperator(String jsonSymbol) {
        this.jsonSymbol = jsonSymbol;
    }

    public String jsonSymbol() {
        return jsonSymbol;
    }

    public static Optional<ComparisonOperator> fromJson(String symbol) {
        return Arrays.stream(values()).filter(op -> op.jsonSymbol.equals(symbol)).findFirst();
    }
}
