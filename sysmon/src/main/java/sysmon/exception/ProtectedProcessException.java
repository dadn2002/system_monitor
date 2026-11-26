package sysmon.exception;

public class ProtectedProcessException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public ProtectedProcessException(String processName) {
        super("Process " + processName + " is critical and cannot be terminated");
    }
}
