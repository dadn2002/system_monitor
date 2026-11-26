package sysmon.exception;

public class DuplicatePidException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public DuplicatePidException(int pid) {
        super("PID " + pid + " already exists in this snapshot");
    }
}
