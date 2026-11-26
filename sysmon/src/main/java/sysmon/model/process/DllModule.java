package sysmon.model.process;

import sysmon.util.Validate;

/** A DLL loaded by a process, as listed by Listdlls. Immutable. (Named DllModule to avoid java.lang.Module.) */
public class DllModule {
    private final String name;
    private final String path;

    public DllModule(String name, String path) {
        this.name = Validate.notBlank(name, "name");
        this.path = (path == null || path.isBlank()) ? null : path.trim();
    }

    public DllModule(String name) { this(name, null); }

    public String getName() { return name; }
    public String getPath() { return path; }

    @Override public String toString() { return name; }
}
