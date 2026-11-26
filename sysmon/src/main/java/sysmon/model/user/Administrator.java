package sysmon.model.user;

import sysmon.enums.Action;
import sysmon.enums.IntegrityLevel;
import sysmon.model.machine.Machine;

/** Full profile. Terminating processes and creating dumps also require an elevated session. */
public class Administrator extends User {
    private boolean elevated;

    public Administrator(String username, String passwordHash, boolean elevated) {
        super(username, passwordHash);
        this.elevated = elevated;
    }

    public boolean isElevated() { return elevated; }
    public void setElevated(boolean elevated) { this.elevated = elevated; }

    @Override public String getRole() { return "ADMINISTRATOR"; }

    @Override public boolean can(Action action) {
        return switch (action) {
            case TERMINATE_PROCESS, CREATE_DUMP -> elevated;
            default -> true;
        };
    }

    @Override public IntegrityLevel getIntegrityLevel() {
        return elevated ? IntegrityLevel.HIGH : IntegrityLevel.MEDIUM;
    }

    @Override public boolean canAccess(Machine machine) { return true; }
}
