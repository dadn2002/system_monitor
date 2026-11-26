package sysmon.model.process;

import sysmon.model.machine.Machine;
import sysmon.util.Validate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * One running process seen on one machine: PID, handles, connections, DLLs.
 * It may point to a ProcessProfile once someone classified it.
 */
public class ProcessInstance {
    private final String id;
    private final int pid;
    private final String name;
    private final String path;
    private final Machine machine;
    private final Instant observedAt;
    private final Instant startedAt;
    private final PermissionSet permissions;
    private ProcessProfile profile;
    private final List<DllModule> modules = new ArrayList<>();
    private final List<Handle> handles = new ArrayList<>();
    private final List<Connection> connections = new ArrayList<>();

    /** @param path       may be null (tasklist does not give it)
     *  @param startedAt  may be null; with the pid it tells apart a reused PID
     *  @param permissions may be null, then PermissionSet.unknown() is used */
    public ProcessInstance(int pid, String name, String path, Machine machine,
                           Instant observedAt, Instant startedAt, PermissionSet permissions) {
        this.id = UUID.randomUUID().toString();
        this.pid = Validate.nonNegative(pid, "pid");
        this.name = Validate.notBlank(name, "name");
        this.path = (path == null || path.isBlank()) ? null : path.trim();
        this.machine = Validate.notNull(machine, "machine");
        this.observedAt = Validate.notNull(observedAt, "observedAt");
        this.startedAt = startedAt;
        this.permissions = permissions == null ? PermissionSet.unknown() : permissions;
    }

    public String getId() { return id; }
    public int getPid() { return pid; }
    public String getName() { return name; }
    public String getPath() { return path; }
    public Machine getMachine() { return machine; }
    public Instant getObservedAt() { return observedAt; }
    public Instant getStartedAt() { return startedAt; }
    public PermissionSet getPermissions() { return permissions; }
    public ProcessProfile getProfile() { return profile; }

    public List<DllModule> getModules() { return Collections.unmodifiableList(modules); }
    public List<Handle> getHandles() { return Collections.unmodifiableList(handles); }
    public List<Connection> getConnections() { return Collections.unmodifiableList(connections); }

    public void addModule(DllModule module) { modules.add(Validate.notNull(module, "module")); }
    public void addHandle(Handle handle) { handles.add(Validate.notNull(handle, "handle")); }
    public void addConnection(Connection connection) { connections.add(Validate.notNull(connection, "connection")); }

    public boolean isClassified() { return profile != null; }
    public void classify(ProcessProfile profile) { this.profile = Validate.notNull(profile, "profile"); }
    public void clearClassification() { this.profile = null; }

    public boolean usesLocalPort(int port) {
        return connections.stream().anyMatch(c -> c.getLocalPort() == port);
    }

    /** PID reuse guard: same pid and name, and the same start time when both are known. */
    public boolean sameProcessAs(ProcessInstance other) {
        if (other == null || pid != other.pid || !name.equalsIgnoreCase(other.name)) return false;
        return startedAt == null || other.startedAt == null || startedAt.equals(other.startedAt);
    }

    @Override public boolean equals(Object o) { return o instanceof ProcessInstance p && id.equals(p.id); }
    @Override public int hashCode() { return Objects.hash(id); }
    @Override public String toString() { return name + " (" + pid + ") on " + machine.getHostname(); }
}
