package sysmon.exception;

public class IncompatibleFileTypeException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public IncompatibleFileTypeException(String toolName, String fileType) {
        super("Tool " + toolName + " does not handle file type " + fileType);
    }
}
