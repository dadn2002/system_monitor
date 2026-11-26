package sysmon.exception;

public class ToolNotInstalledException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public ToolNotInstalledException(String toolName, String path) {
        super("Tool " + toolName + " is not installed at " + path);
    }
}
