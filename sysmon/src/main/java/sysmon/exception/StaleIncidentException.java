package sysmon.exception;

public class StaleIncidentException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public StaleIncidentException(String incidentId, int expected, int actual) {
        super("Incident " + incidentId + " was changed by someone else (expected version "
                + expected + ", current " + actual + ")");
    }
}
