package sysmon.exception;

public class ValidationException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public ValidationException(String message) {
        super(message);
    }
}
