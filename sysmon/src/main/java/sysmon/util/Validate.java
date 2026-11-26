package sysmon.util;

import sysmon.exception.ValidationException;

/** Small helpers so every entity validates its data the same way. */
public final class Validate {
    private Validate() {}

    public static String notBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new ValidationException(field + " must not be blank");
        }
        return value.trim();
    }

    public static <T> T notNull(T value, String field) {
        if (value == null) {
            throw new ValidationException(field + " must not be null");
        }
        return value;
    }

    public static int positive(int value, String field) {
        if (value <= 0) {
            throw new ValidationException(field + " must be greater than zero (got " + value + ")");
        }
        return value;
    }

    public static int nonNegative(int value, String field) {
        if (value < 0) {
            throw new ValidationException(field + " must not be negative (got " + value + ")");
        }
        return value;
    }

    /** Normalizes a file type to lower case with a leading dot: "DMP" -> ".dmp". */
    public static String fileType(String value) {
        String v = notBlank(value, "fileType").toLowerCase();
        return v.startsWith(".") ? v : "." + v;
    }
}
