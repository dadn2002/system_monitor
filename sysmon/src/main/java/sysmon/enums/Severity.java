package sysmon.enums;

/** Event Viewer levels, ordered from least to most severe. */
public enum Severity {
    INFORMATION, WARNING, ERROR, CRITICAL;

    public boolean atLeast(Severity other) {
        return this.compareTo(other) >= 0;
    }
}
