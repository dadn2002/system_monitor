package sysmon.model.incident;

import sysmon.enums.Action;
import sysmon.enums.ExecutionState;
import sysmon.exception.IncompatibleFileTypeException;
import sysmon.exception.InsufficientPrivilegeException;
import sysmon.exception.InvalidStateTransitionException;
import sysmon.model.process.ProcessInstance;
import sysmon.model.tool.Tool;
import sysmon.model.user.User;
import sysmon.util.Validate;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * One run of a Tool against a ProcessInstance by a User.
 * The constructor applies the rules that involve several classes; the state methods apply the lifecycle.
 */
public class ToolExecution {
    private final String id;
    private final Tool tool;
    private final ProcessInstance target;
    private final User requestedBy;
    private final Instant requestedAt;
    private final List<String> command;
    private ExecutionState state = ExecutionState.PENDING;
    private Instant startedAt;
    private Instant finishedAt;
    private String outputFile;
    private String failureReason;

    public ToolExecution(Tool tool, ProcessInstance target, User requestedBy) {
        Validate.notNull(tool, "tool");
        Validate.notNull(target, "target");
        Validate.notNull(requestedBy, "requestedBy");

        requestedBy.requireCan(Action.RUN_TOOL);
        if (!requestedBy.canAccess(target.getMachine())) {
            throw new InsufficientPrivilegeException(requestedBy.getUsername()
                    + " has no access to machine " + target.getMachine().getHostname());
        }
        if (!requestedBy.getIntegrityLevel().atLeast(tool.requiredIntegrity())) {
            throw new InsufficientPrivilegeException(tool.getName() + " needs integrity "
                    + tool.requiredIntegrity() + " but " + requestedBy.getUsername()
                    + " runs at " + requestedBy.getIntegrityLevel());
        }
        if (!target.getPermissions().canBeInspectedBy(requestedBy.getIntegrityLevel())) {
            throw new InsufficientPrivilegeException(target.getName() + " runs at "
                    + target.getPermissions().getIntegrityLevel() + ", above " + requestedBy.getUsername()
                    + "'s level " + requestedBy.getIntegrityLevel());
        }
        tool.ensureInstalled();
        if (target.isClassified()) {
            target.getProfile().checkTool(tool);
        }

        this.id = UUID.randomUUID().toString();
        this.tool = tool;
        this.target = target;
        this.requestedBy = requestedBy;
        this.requestedAt = Instant.now();
        this.command = List.copyOf(tool.buildCommand(target));
    }

    public String getId() { return id; }
    public Tool getTool() { return tool; }
    public ProcessInstance getTarget() { return target; }
    public User getRequestedBy() { return requestedBy; }
    public Instant getRequestedAt() { return requestedAt; }
    public List<String> getCommand() { return command; }
    public ExecutionState getState() { return state; }
    public Instant getStartedAt() { return startedAt; }
    public Instant getFinishedAt() { return finishedAt; }
    public String getOutputFile() { return outputFile; }
    public String getFailureReason() { return failureReason; }

    public void start() {
        moveTo(ExecutionState.RUNNING);
        startedAt = Instant.now();
    }

    /** The output file, when there is one, must be of a type the tool handles. */
    public void complete(String outputFile) {
        if (!state.canMoveTo(ExecutionState.COMPLETED)) {
            throw new InvalidStateTransitionException("ToolExecution", state, ExecutionState.COMPLETED);
        }
        if (outputFile != null && !outputFile.isBlank()) {
            int dot = outputFile.lastIndexOf('.');
            if (dot < 0 || !tool.supports(outputFile.substring(dot))) {
                throw new IncompatibleFileTypeException(tool.getName(),
                        dot < 0 ? "(no extension)" : outputFile.substring(dot));
            }
            this.outputFile = outputFile.trim();
        }
        moveTo(ExecutionState.COMPLETED);
        finishedAt = Instant.now();
    }

    public void fail(String reason) {
        moveTo(ExecutionState.FAILED);
        failureReason = Validate.notBlank(reason, "reason");
        finishedAt = Instant.now();
    }

    public void cancel() {
        moveTo(ExecutionState.CANCELLED);
        finishedAt = Instant.now();
    }

    public boolean isCompleted() { return state == ExecutionState.COMPLETED; }

    private void moveTo(ExecutionState next) {
        if (!state.canMoveTo(next)) throw new InvalidStateTransitionException("ToolExecution", state, next);
        state = next;
    }

    @Override public String toString() { return tool.getName() + " -> " + target + " [" + state + "]"; }
}
