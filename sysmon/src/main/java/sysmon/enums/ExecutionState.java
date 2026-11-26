package sysmon.enums;

import java.util.EnumSet;
import java.util.Set;

/** PENDING -> RUNNING -> COMPLETED | FAILED;  PENDING -> CANCELLED. */
public enum ExecutionState {
    PENDING, RUNNING, COMPLETED, FAILED, CANCELLED;

    public Set<ExecutionState> allowedNext() {
        return switch (this) {
            case PENDING -> EnumSet.of(RUNNING, CANCELLED);
            case RUNNING -> EnumSet.of(COMPLETED, FAILED);
            case COMPLETED, FAILED, CANCELLED -> EnumSet.noneOf(ExecutionState.class);
        };
    }

    public boolean canMoveTo(ExecutionState next) {
        return allowedNext().contains(next);
    }
}
