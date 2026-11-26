package sysmon.enums;

public enum HandleType {
    PROCESS, THREAD, FILE, DIRECTORY, OTHER;

    /** Parses the type column printed by handle.exe ("Process", "Thread", ...). */
    public static HandleType fromString(String raw) {
        if (raw == null) return OTHER;
        try {
            return valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return OTHER;
        }
    }
}
