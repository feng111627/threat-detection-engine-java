package com.github.feng111627.threatdetectionenginejava.engine;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 某个 (规则, 实体, 时间窗口) 的关联状态。
 *
 * <p>记录窗口内出现过的去重事件 ID（幂等去重），以及该窗口是否已告警。
 * 本对象不是线程安全的；{@link DetectionEngine} 保证对同一窗口状态的访问在同一把锁内进行。
 */
public final class WindowState {

    private final Set<String> distinctEventIds = new LinkedHashSet<>();
    private boolean alerted = false;

    /**
     * 观察一个事件：重复投递（eventId 已在窗口内）返回 false 且不改变计数；
     * 新事件加入集合返回 true。
     */
    public boolean observe(String eventId) {
        return distinctEventIds.add(eventId);
    }

    public int count() {
        return distinctEventIds.size();
    }

    public boolean isAlerted() {
        return alerted;
    }

    /**
     * 尝试把窗口标记为已告警：仅首次返回 true（由它产生告警），
     * 并发或重复到达时后续调用返回 false（不重复告警）。
     */
    public boolean markAlerted() {
        if (alerted) {
            return false;
        }
        alerted = true;
        return true;
    }

    /** 当前参与计数的事件 ID（有序，用于告警解释）。 */
    public Set<String> eventIds() {
        return Set.copyOf(distinctEventIds);
    }
}
