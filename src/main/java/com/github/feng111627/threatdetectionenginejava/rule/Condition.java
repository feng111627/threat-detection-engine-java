package com.github.feng111627.threatdetectionenginejava.rule;

import com.github.feng111627.threatdetectionenginejava.model.EventSchema;
import com.github.feng111627.threatdetectionenginejava.model.SecurityEvent;
import java.util.List;

/** 规则过滤条件。 */
public interface Condition {

    /** 事件是否满足该条件。 */
    boolean matches(SecurityEvent event);

    /** 对照事件 schema 校验条件，返回所有问题（空列表表示通过）。 */
    List<ConditionIssue> validate(EventSchema schema);
}
