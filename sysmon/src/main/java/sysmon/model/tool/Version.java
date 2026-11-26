package sysmon.model.tool;

import sysmon.exception.ValidationException;
import sysmon.util.Validate;

import java.util.Arrays;

/** Dotted numeric version such as "5.0" or "11.1.2". Immutable and comparable. */
public class Version implements Comparable<Version> {
    private final String text;

    public Version(String text) {
        this.text = Validate.notBlank(text, "version");
        parts(); // fails fast on malformed input
    }

    public String getText() { return text; }

    private int[] parts() {
        try {
            return Arrays.stream(text.split("\\.")).mapToInt(Integer::parseInt).toArray();
        } catch (NumberFormatException e) {
            throw new ValidationException("version must be dotted numbers like 1.2.3 (got " + text + ")");
        }
    }

    @Override public int compareTo(Version other) {
        int[] a = parts(), b = other.parts();
        for (int i = 0; i < Math.max(a.length, b.length); i++) {
            int x = i < a.length ? a[i] : 0;
            int y = i < b.length ? b[i] : 0;
            if (x != y) return Integer.compare(x, y);
        }
        return 0;
    }

    public boolean atLeast(Version minimum) { return compareTo(minimum) >= 0; }

    @Override public boolean equals(Object o) { return o instanceof Version v && compareTo(v) == 0; }
    @Override public int hashCode() { return Arrays.hashCode(trimmed()); }
    private int[] trimmed() {
        int[] p = parts();
        int n = p.length;
        while (n > 1 && p[n - 1] == 0) n--;
        return Arrays.copyOf(p, n);
    }
    @Override public String toString() { return text; }
}
