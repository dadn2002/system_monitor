package sysmon.model.machine;

import sysmon.util.Validate;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A computer where snapshots were collected. */
public class Machine {
    private final String id;
    private final Instant registeredAt;
    private String hostname;
    private String osVersion;
    private String label;

    public Machine(String hostname, String osVersion) {
        this.id = UUID.randomUUID().toString();
        this.registeredAt = Instant.now();
        setHostname(hostname);
        setOsVersion(osVersion);
    }

    public String getId() { return id; }
    public Instant getRegisteredAt() { return registeredAt; }
    public String getHostname() { return hostname; }
    public String getOsVersion() { return osVersion; }
    public String getLabel() { return label; }

    public final void setHostname(String hostname) { this.hostname = Validate.notBlank(hostname, "hostname"); }
    public final void setOsVersion(String osVersion) { this.osVersion = Validate.notBlank(osVersion, "osVersion"); }
    /** Free text such as "lab PC 3" or "dev laptop". May be null. */
    public void setLabel(String label) { this.label = (label == null || label.isBlank()) ? null : label.trim(); }

    @Override public boolean equals(Object o) { return o instanceof Machine m && id.equals(m.id); }
    @Override public int hashCode() { return Objects.hash(id); }
    @Override public String toString() { return hostname + " (" + osVersion + ")"; }
}
