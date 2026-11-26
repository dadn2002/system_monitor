package sysmon.enums;

/** Windows integrity levels, ordered from least to most privileged. */
public enum IntegrityLevel {
    LOW, MEDIUM, HIGH, SYSTEM;

    public boolean atLeast(IntegrityLevel other) {
        return this.compareTo(other) >= 0;
    }
}
