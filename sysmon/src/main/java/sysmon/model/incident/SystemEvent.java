package sysmon.model.incident;

import sysmon.enums.Severity;
import sysmon.model.machine.Machine;
import sysmon.model.process.ProcessInstance;
import sysmon.util.Validate;

import java.time.Instant;
import java.util.UUID;

/** One Event Viewer entry stored in the system. Immutable. */
public class SystemEvent {
    private final String id;
    private final Machine machine;
    private final Instant timestamp;
    private final String source;
    private final int eventId;
    private final Severity severity;
    private final String message;
    private final ProcessInstance relatedProcess;

    /** @param relatedProcess may be null when the event cannot be tied to a process */
    public SystemEvent(Machine machine, Instant timestamp, String source, int eventId,
                       Severity severity, String message, ProcessInstance relatedProcess) {
        this.id = UUID.randomUUID().toString();
        this.machine = Validate.notNull(machine, "machine");
        this.timestamp = Validate.notNull(timestamp, "timestamp");
        this.source = Validate.notBlank(source, "source");
        this.eventId = Validate.nonNegative(eventId, "eventId");
        this.severity = Validate.notNull(severity, "severity");
        this.message = Validate.notBlank(message, "message");
        this.relatedProcess = relatedProcess;
    }

    public String getId() { return id; }
    public Machine getMachine() { return machine; }
    public Instant getTimestamp() { return timestamp; }
    public String getSource() { return source; }
    public int getEventId() { return eventId; }
    public Severity getSeverity() { return severity; }
    public String getMessage() { return message; }
    public ProcessInstance getRelatedProcess() { return relatedProcess; }

    public boolean isCritical() { return severity == Severity.CRITICAL; }

    @Override public String toString() { return "[" + severity + "] " + source + " #" + eventId + " on " + machine.getHostname(); }
}
