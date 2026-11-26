package sysmon.exception;

public class NoNetworkActivityException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public NoNetworkActivityException(String processName, int pid) {
        super("Process " + processName + " (" + pid + ") has no network connections to inspect");
    }
}
