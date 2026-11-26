package sysmon.exception;

public class MissingEvidenceException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public MissingEvidenceException(String incidentId) {
        super("Incident " + incidentId + " cannot be resolved without a completed tool execution as evidence");
    }
}
