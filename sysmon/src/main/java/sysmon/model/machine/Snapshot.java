package sysmon.model.machine;

import sysmon.enums.Protocol;
import sysmon.exception.DuplicatePidException;
import sysmon.exception.ValidationException;
import sysmon.model.process.Connection;
import sysmon.model.process.ProcessInstance;
import sysmon.util.Validate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Everything observed on one machine during one run of the collector. */
public class Snapshot {
    private final String id;
    private final Machine machine;
    private final Instant takenAt;
    private final List<ProcessInstance> instances = new ArrayList<>();

    public Snapshot(Machine machine, Instant takenAt) {
        this.id = UUID.randomUUID().toString();
        this.machine = Validate.notNull(machine, "machine");
        this.takenAt = Validate.notNull(takenAt, "takenAt");
    }

    public String getId() { return id; }
    public Machine getMachine() { return machine; }
    public Instant getTakenAt() { return takenAt; }
    public List<ProcessInstance> getInstances() { return Collections.unmodifiableList(instances); }

    /** Rules: the instance must come from this snapshot's machine, and PIDs are unique inside a snapshot. */
    public void add(ProcessInstance instance) {
        Validate.notNull(instance, "instance");
        if (!instance.getMachine().equals(machine)) {
            throw new ValidationException("Process " + instance.getName() + " belongs to "
                    + instance.getMachine().getHostname() + ", not to " + machine.getHostname());
        }
        if (findByPid(instance.getPid()).isPresent()) {
            throw new DuplicatePidException(instance.getPid());
        }
        instances.add(instance);
    }

    public Optional<ProcessInstance> findByPid(int pid) {
        return instances.stream().filter(i -> i.getPid() == pid).findFirst();
    }

    /** The "to classify" queue: observed processes without a catalog profile. */
    public List<ProcessInstance> findUnclassified() {
        return instances.stream().filter(i -> !i.isClassified()).toList();
    }

    /** Processes that use the given local port (any protocol). */
    public List<ProcessInstance> findByLocalPort(int port) {
        return instances.stream().filter(i -> i.usesLocalPort(port)).toList();
    }

    public List<ProcessInstance> findByLocalPort(int port, Protocol protocol) {
        return instances.stream()
                .filter(i -> i.getConnections().stream()
                        .anyMatch(c -> c.getProtocol() == protocol && c.getLocalPort() == port))
                .toList();
    }

    @Override public String toString() { return "Snapshot " + machine.getHostname() + " @ " + takenAt; }
}
