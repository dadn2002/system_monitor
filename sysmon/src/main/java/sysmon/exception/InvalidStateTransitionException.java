package sysmon.exception;

public class InvalidStateTransitionException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public InvalidStateTransitionException(String entity, Object from, Object to) {
        super(entity + " cannot move from " + from + " to " + to);
    }
}
