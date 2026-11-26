package sysmon.model.user;

import sysmon.enums.Action;
import sysmon.enums.IntegrityLevel;
import sysmon.exception.InsufficientPrivilegeException;
import sysmon.model.machine.Machine;
import sysmon.util.Validate;

import java.time.Instant;
import java.util.UUID;

/** Someone who can log in. Subclasses decide what they are allowed to do. */
public abstract class User {
    private final String id;
    private final Instant createdAt;
    private String username;
    private String passwordHash;
    private boolean active = true;

    protected User(String username, String passwordHash) {
        this.id = UUID.randomUUID().toString();
        this.createdAt = Instant.now();
        setUsername(username);
        setPasswordHash(passwordHash);
    }

    public String getId() { return id; }
    public Instant getCreatedAt() { return createdAt; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public boolean isActive() { return active; }

    public final void setUsername(String username) { this.username = Validate.notBlank(username, "username"); }
    /** Always a hash, never the clear password (hashing is done by the auth service). */
    public final void setPasswordHash(String hash) { this.passwordHash = Validate.notBlank(hash, "passwordHash"); }
    public void setActive(boolean active) { this.active = active; }

    public abstract String getRole();
    /** Polymorphic: may this user perform the action? */
    public abstract boolean can(Action action);
    /** Polymorphic: the integrity level this user operates at. */
    public abstract IntegrityLevel getIntegrityLevel();
    /** Polymorphic: may this user work on that machine? */
    public abstract boolean canAccess(Machine machine);

    public void requireCan(Action action) {
        if (!active) throw new InsufficientPrivilegeException("User " + username + " is disabled");
        if (!can(action)) {
            throw new InsufficientPrivilegeException(getRole() + " " + username + " is not allowed to " + action);
        }
    }

    @Override public String toString() { return getRole() + " " + username; }
}
