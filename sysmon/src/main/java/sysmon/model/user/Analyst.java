package sysmon.model.user;

import sysmon.enums.Action;
import sysmon.enums.IntegrityLevel;
import sysmon.model.machine.Machine;
import sysmon.util.Validate;

import java.util.HashSet;
import java.util.Set;

/** Read-oriented profile: classifies processes and runs non-invasive tools, only on assigned machines. */
public class Analyst extends User {
    private final Set<String> assignedMachineIds = new HashSet<>();

    public Analyst(String username, String passwordHash) { super(username, passwordHash); }

    public Set<String> getAssignedMachineIds() { return Set.copyOf(assignedMachineIds); }

    public void assign(Machine machine) { assignedMachineIds.add(Validate.notNull(machine, "machine").getId()); }
    public void unassign(Machine machine) { assignedMachineIds.remove(Validate.notNull(machine, "machine").getId()); }

    @Override public String getRole() { return "ANALYST"; }

    @Override public boolean can(Action action) {
        return switch (action) {
            case VIEW, CLASSIFY, RUN_TOOL, MANAGE_INCIDENTS -> true;
            default -> false;
        };
    }

    @Override public IntegrityLevel getIntegrityLevel() { return IntegrityLevel.MEDIUM; }

    @Override public boolean canAccess(Machine machine) { return assignedMachineIds.contains(machine.getId()); }
}
