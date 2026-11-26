package sysmon.exception;

/** Base type for every error this application raises on purpose. Unchecked, so validation stays readable. */
public class SysmonException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public SysmonException(String message) {
        super(message);
    }
}
