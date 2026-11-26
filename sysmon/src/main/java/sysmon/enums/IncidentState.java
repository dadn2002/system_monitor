package sysmon.enums;

import java.util.EnumSet;
import java.util.Set;

/**
 * NEW -> TRIAGED -> INVESTIGATING -> RESOLVED
 * NEW / TRIAGED -> DISMISSED        RESOLVED -> INVESTIGATING (reopen)
 */
public enum IncidentState {
    NEW, TRIAGED, INVESTIGATING, RESOLVED, DISMISSED;

    public Set<IncidentState> allowedNext() {
        return switch (this) {
            case NEW -> EnumSet.of(TRIAGED, DISMISSED);
            case TRIAGED -> EnumSet.of(INVESTIGATING, DISMISSED);
            case INVESTIGATING -> EnumSet.of(RESOLVED);
            case RESOLVED -> EnumSet.of(INVESTIGATING);
            case DISMISSED -> EnumSet.noneOf(IncidentState.class);
        };
    }

    public boolean canMoveTo(IncidentState next) {
        return allowedNext().contains(next);
    }
}
