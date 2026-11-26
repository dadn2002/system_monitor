package sysmon.enums;

import sysmon.exception.ValidationException;

public enum Protocol {
    TCP, UDP;

    /** Parses the protocol column printed by netstat ("TCP", "UDP"). */
    public static Protocol fromString(String raw) {
        if (raw == null) throw new ValidationException("protocol must not be null");
        String v = raw.trim().toUpperCase();
        if (v.startsWith("TCP")) return TCP;
        if (v.startsWith("UDP")) return UDP;
        throw new ValidationException("unknown protocol: " + raw);
    }
}
