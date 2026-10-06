package com.github.feng111627.threatdetectionenginejava.rule;

import com.github.feng111627.threatdetectionenginejava.model.EventSchema;
import com.github.feng111627.threatdetectionenginejava.model.FieldType;
import com.github.feng111627.threatdetectionenginejava.model.SecurityEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** 叶子条件：field op value。 */
public final class LeafCondition implements Condition {

    private final String field;
    private final ComparisonOperator operator;
    private final Object value;

    public LeafCondition(String field, ComparisonOperator operator, Object value) {
        this.field = field;
        this.operator = Objects.requireNonNull(operator, "operator");
        this.value = value;
    }

    public String getField() { return field; }
    public ComparisonOperator getOperator() { return operator; }
    public Object getValue() { return value; }

    @Override
    public boolean matches(SecurityEvent event) {
        Object actual = event.getField(field);
        return apply(actual, operator, value);
    }

    private static boolean apply(Object actual, ComparisonOperator op, Object expected) {
        if (actual == null) {
            // null 只参与 != 判定：null != 非null 为 true；其余运算均不成立
            return op == ComparisonOperator.NE && expected != null;
        }
        switch (op) {
            case EQ:
                return looseEquals(actual, expected);
            case NE:
                return !looseEquals(actual, expected);
            case GT, GTE, LT, LTE:
                return compare(actual, expected, op);
            case CONTAINS:
                return actual instanceof String s && expected instanceof String e && s.contains(e);
            case STARTS_WITH:
                return actual instanceof String s && expected instanceof String e && s.startsWith(e);
            case ENDS_WITH:
                return actual instanceof String s && expected instanceof String e && s.endsWith(e);
            case IN:
                if (expected instanceof Collection<?> c) {
                    for (Object item : c) {
                        if (looseEquals(actual, item)) {
                            return true;
                        }
                    }
                }
                return false;
            default:
                return false;
        }
    }

    private static boolean compare(Object actual, Object expected, ComparisonOperator op) {
        int cmp;
        if (actual instanceof Instant a && expected instanceof Instant e) {
            cmp = a.compareTo(e);
        } else if (actual instanceof Number a && expected instanceof Number e) {
            cmp = Double.compare(a.doubleValue(), e.doubleValue());
        } else {
            return false;
        }
        return switch (op) {
            case GT -> cmp > 0;
            case GTE -> cmp >= 0;
            case LT -> cmp < 0;
            case LTE -> cmp <= 0;
            default -> false;
        };
    }

    /** 数字按数值比较（忽略 Long/Double 装箱差异），其余按 equals。 */
    private static boolean looseEquals(Object a, Object b) {
        if (a instanceof Number x && b instanceof Number y) {
            return Double.compare(x.doubleValue(), y.doubleValue()) == 0;
        }
        return Objects.equals(a, b);
    }

    @Override
    public List<ConditionIssue> validate(EventSchema schema) {
        List<ConditionIssue> issues = new ArrayList<>();
        if (field == null || field.isBlank()) {
            issues.add(new ConditionIssue(RuleFailureReason.MISSING_REQUIRED_FIELD,
                    "condition.field 不能为空"));
            return issues;
        }
        if (!schema.exists(field)) {
            issues.add(new ConditionIssue(RuleFailureReason.UNKNOWN_FIELD,
                    "条件引用了不存在的字段: '" + field + "'"));
            return issues;
        }
        if (value == null) {
            issues.add(new ConditionIssue(RuleFailureReason.INVALID_VALUE,
                    "字段 '" + field + "' 的比较值不能为 null"));
            return issues;
        }
        Optional<FieldType> declared = schema.fieldType(field);
        if (declared.isPresent()) {
            checkDeclaredType(issues, declared.get());
        } else {
            checkOperatorValueShape(issues);
        }
        return issues;
    }

    /** 标准字段：要求值类型与 schema 声明类型及运算符兼容。 */
    private void checkDeclaredType(List<ConditionIssue> issues, FieldType type) {
        boolean valueOk = switch (type) {
            case STRING -> value instanceof String && isStringCompatibleOp();
            case LONG, DOUBLE -> value instanceof Number && isOrderOrEqualityOp();
            case BOOLEAN -> value instanceof Boolean && (operator == ComparisonOperator.EQ
                    || operator == ComparisonOperator.NE);
            case INSTANT -> value instanceof Instant && isOrderOrEqualityOp();
        };
        if (!valueOk) {
            issues.add(new ConditionIssue(RuleFailureReason.TYPE_MISMATCH,
                    "字段 '" + field + "' 声明为 " + type + "，与运算符 " + operator.jsonSymbol()
                            + " 及值类型 " + value.getClass().getSimpleName() + " 不兼容"));
        }
    }

    /** attr.* 动态属性：至少保证运算符需要的值形态正确。 */
    private void checkOperatorValueShape(List<ConditionIssue> issues) {
        boolean ok = switch (operator) {
            case EQ, NE -> true;
            case GT, GTE, LT, LTE -> value instanceof Number || value instanceof Instant;
            case CONTAINS, STARTS_WITH, ENDS_WITH -> value instanceof String;
            case IN -> value instanceof Collection<?> c && !c.isEmpty();
        };
        if (!ok) {
            issues.add(new ConditionIssue(RuleFailureReason.TYPE_MISMATCH,
                    "动态属性 '" + field + "' 的运算符 " + operator.jsonSymbol()
                            + " 与值类型 " + value.getClass().getSimpleName() + " 不兼容"));
        }
    }

    private boolean isStringCompatibleOp() {
        return switch (operator) {
            case EQ, NE, CONTAINS, STARTS_WITH, ENDS_WITH, IN -> true;
            default -> false;
        };
    }

    private boolean isOrderOrEqualityOp() {
        return switch (operator) {
            case EQ, NE, GT, GTE, LT, LTE -> true;
            default -> false;
        };
    }
}
