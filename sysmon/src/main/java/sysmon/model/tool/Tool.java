package sysmon.model.tool;

import sysmon.enums.IntegrityLevel;
import sysmon.exception.ToolNotInstalledException;
import sysmon.exception.ValidationException;
import sysmon.model.process.ProcessInstance;
import sysmon.util.Validate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** An external analysis program (Procmon, WinDbg, Wireshark, ProcDump, Sysmon, handle.exe...). */
public abstract class Tool {
    private final String id;
    private String name;
    private String description;
    private String defaultPath;
    private Version version;
    private Set<String> fileTypes;
    private String docWebsite;

    protected Tool(String name, String description, String defaultPath, Version version,
                   Collection<String> fileTypes, String docWebsite) {
        this.id = UUID.randomUUID().toString();
        setName(name);
        setDescription(description);
        setDefaultPath(defaultPath);
        setVersion(version);
        setFileTypes(fileTypes);
        setDocWebsite(docWebsite);
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    /** Kept as text so it serializes to JSON unchanged; use resolvePath() when you need a Path. */
    public String getDefaultPath() { return defaultPath; }
    public Version getVersion() { return version; }
    public Set<String> getFileTypes() { return fileTypes; }
    public String getDocWebsite() { return docWebsite; }

    public final void setName(String name) { this.name = Validate.notBlank(name, "name"); }
    public final void setDescription(String description) { this.description = Validate.notBlank(description, "description"); }
    public final void setDefaultPath(String defaultPath) { this.defaultPath = Validate.notBlank(defaultPath, "defaultPath"); }
    public final void setVersion(Version version) { this.version = Validate.notNull(version, "version"); }

    public final void setFileTypes(Collection<String> fileTypes) {
        Validate.notNull(fileTypes, "fileTypes");
        Set<String> normalized = new LinkedHashSet<>();
        for (String t : fileTypes) normalized.add(Validate.fileType(t));
        this.fileTypes = Set.copyOf(normalized);
    }

    public final void setDocWebsite(String docWebsite) {
        String url = Validate.notBlank(docWebsite, "docWebsite");
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw new ValidationException("docWebsite must start with http:// or https:// (got " + url + ")");
        }
        this.docWebsite = url;
    }

    /** Short label used in reports and in JSON ("NETWORK", "HANDLE", "DEBUG"). */
    public abstract String getKind();

    /**
     * Polymorphic: the full command line (program + arguments, no shell string) to run this tool
     * against the target. Building an argument list instead of a shell string avoids injection.
     */
    public abstract List<String> buildCommand(ProcessInstance target);

    /** Polymorphic: the minimum integrity level a user needs to run this tool. */
    public IntegrityLevel requiredIntegrity() { return IntegrityLevel.MEDIUM; }

    public Path resolvePath() { return Path.of(defaultPath); }
    public boolean isInstalled() { return Files.isRegularFile(resolvePath()); }

    public void ensureInstalled() {
        if (!isInstalled()) throw new ToolNotInstalledException(name, defaultPath);
    }

    public boolean supports(String fileType) { return fileTypes.contains(Validate.fileType(fileType)); }
    public boolean meetsMinimum(Version minimum) { return version.atLeast(minimum); }

    @Override public String toString() { return "[" + getKind() + "] " + name + " " + version; }
}
