package sysmon.model.process;

import sysmon.enums.IntegrityLevel;
import sysmon.util.Validate;

import java.util.Collection;
import java.util.Set;

/** The security context a process runs in: integrity level, account and privileges. Immutable. */
public class PermissionSet {
    private final IntegrityLevel integrityLevel;
    private final String userAccount;
    private final Set<String> privileges;

    public PermissionSet(IntegrityLevel integrityLevel, String userAccount, Collection<String> privileges) {
        this.integrityLevel = Validate.notNull(integrityLevel, "integrityLevel");
        this.userAccount = Validate.notBlank(userAccount, "userAccount");
        this.privileges = privileges == null ? Set.of() : Set.copyOf(privileges);
    }

    /** The collector does not capture security data yet, so imported processes start with this. */
    public static PermissionSet unknown() {
        return new PermissionSet(IntegrityLevel.MEDIUM, "unknown", Set.of());
    }

    public IntegrityLevel getIntegrityLevel() { return integrityLevel; }
    public String getUserAccount() { return userAccount; }
    public Set<String> getPrivileges() { return privileges; }

    public boolean hasPrivilege(String privilege) { return privileges.contains(privilege); }

    /** A caller can only inspect processes whose integrity is not above its own. */
    public boolean canBeInspectedBy(IntegrityLevel viewer) {
        return viewer.atLeast(integrityLevel);
    }

    @Override public String toString() { return userAccount + " [" + integrityLevel + "]"; }
}
