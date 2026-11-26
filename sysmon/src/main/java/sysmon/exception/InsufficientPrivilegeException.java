package sysmon.exception;

public class InsufficientPrivilegeException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public InsufficientPrivilegeException(String message) {
        super(message);
    }
}
