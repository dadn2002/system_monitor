package sysmon.model.process;

import sysmon.exception.ProtectedProcessException;
import sysmon.model.tool.Tool;
import sysmon.util.Validate;

import java.util.UUID;

/**
 * Catalog entry: "what is this program", independent of any machine or PID.
 * Named ProcessProfile to avoid clashing with java.lang.Process.
 */
public abstract class ProcessProfile {
    private final String id;
    private String name;
    private String description;
    private String path;

    protected ProcessProfile(String name, String description, String path) {
        this.id = UUID.randomUUID().toString();
        setName(name);
        setDescription(description);
        setPath(path);
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public String getPath() { return path; }

    public final void setName(String name) { this.name = Validate.notBlank(name, "name"); }
    public final void setDescription(String description) { this.description = Validate.notBlank(description, "description"); }
    /** Expected executable path. May be null when unknown. */
    public final void setPath(String path) { this.path = (path == null || path.isBlank()) ? null : path.trim(); }

    /** Category label used in reports and in JSON ("SYSTEM", "GAME", "BROWSER"). */
    public abstract String getCategory();

    /** Polymorphic rule: may this kind of process be terminated? */
    public abstract boolean canBeTerminated();

    /** Polymorphic rule: throws if the tool must not be used on this kind of process. Default: allowed. */
    public void checkTool(Tool tool) { }

    public void ensureTerminable() {
        if (!canBeTerminated()) throw new ProtectedProcessException(name);
    }

    /** Catalog matching: same name (ignoring case) and, when both sides know it, same path. */
    public boolean matches(String observedName, String observedPath) {
        if (observedName == null || !name.equalsIgnoreCase(observedName.trim())) return false;
        if (path == null || observedPath == null || observedPath.isBlank()) return true;
        return path.equalsIgnoreCase(observedPath.trim());
    }

    @Override public String toString() { return "[" + getCategory() + "] " + name; }
}
