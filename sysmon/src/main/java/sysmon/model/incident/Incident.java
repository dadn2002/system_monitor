package sysmon.model.incident;

import sysmon.enums.Action;
import sysmon.enums.IncidentState;
import sysmon.enums.Severity;
import sysmon.exception.InvalidStateTransitionException;
import sysmon.exception.MissingEvidenceException;
import sysmon.exception.StaleIncidentException;
import sysmon.model.user.User;
import sysmon.util.Validate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/** A problem under investigation. It groups events and tool runs and follows a strict state machine. */
public class Incident {
    private final String id;
    private final Instant openedAt;
    private String title;
    private IncidentState state = IncidentState.NEW;
    private int version = 1;
    private User assignee;
    private final List<SystemEvent> events = new ArrayList<>();
    private final List<ToolExecution> evidence = new ArrayList<>();
    private final List<String> notes = new ArrayList<>();

    public Incident(String title, SystemEvent firstEvent) {
        this.id = UUID.randomUUID().toString();
        this.openedAt = Instant.now();
        this.title = Validate.notBlank(title, "title");
        events.add(Validate.notNull(firstEvent, "firstEvent"));
    }

    public String getId() { return id; }
    public Instant getOpenedAt() { return openedAt; }
    public String getTitle() { return title; }
    public IncidentState getState() { return state; }
    /** Optimistic lock counter: every change increments it. */
    public int getVersion() { return version; }
    public User getAssignee() { return assignee; }
    public List<SystemEvent> getEvents() { return Collections.unmodifiableList(events); }
    public List<ToolExecution> getEvidence() { return Collections.unmodifiableList(evidence); }
    public List<String> getNotes() { return Collections.unmodifiableList(notes); }

    /** The worst severity among the grouped events. */
    public Severity getSeverity() {
        return events.stream().map(SystemEvent::getSeverity).max(Severity::compareTo).orElse(Severity.INFORMATION);
    }

    public void setTitle(String title) {
        this.title = Validate.notBlank(title, "title");
        version++;
    }

    public void addEvent(SystemEvent event) {
        events.add(Validate.notNull(event, "event"));
        version++;
    }

    public void addEvidence(ToolExecution execution) {
        evidence.add(Validate.notNull(execution, "execution"));
        version++;
    }

    public void addNote(String note) {
        notes.add(Validate.notBlank(note, "note"));
        version++;
    }

    public void assignTo(User user) {
        Validate.notNull(user, "user").requireCan(Action.MANAGE_INCIDENTS);
        this.assignee = user;
        version++;
    }

    public boolean hasCompletedEvidence() {
        return evidence.stream().anyMatch(ToolExecution::isCompleted);
    }

    /**
     * Rules: the caller may manage incidents; the version the caller saw must still be current;
     * the transition must be allowed; RESOLVED needs at least one completed tool execution.
     */
    public void moveTo(IncidentState next, int expectedVersion, User by) {
        Validate.notNull(next, "next");
        Validate.notNull(by, "by").requireCan(Action.MANAGE_INCIDENTS);
        if (expectedVersion != version) {
            throw new StaleIncidentException(id, expectedVersion, version);
        }
        if (!state.canMoveTo(next)) {
            throw new InvalidStateTransitionException("Incident", state, next);
        }
        if (next == IncidentState.RESOLVED && !hasCompletedEvidence()) {
            throw new MissingEvidenceException(id);
        }
        state = next;
        version++;
    }

    @Override public String toString() { return "Incident \"" + title + "\" [" + state + ", v" + version + "]"; }
}
