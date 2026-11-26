package sysmon.model.tool;

import sysmon.enums.IntegrityLevel;
import sysmon.exception.ValidationException;
import sysmon.model.process.ProcessInstance;
import sysmon.util.Validate;

import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

/** Debuggers and dump tools (WinDbg, ProcDump...). */
public class DebugTool extends Tool {
    private boolean supportsDump;
    private String dumpDirectory;

    public DebugTool(String name, String description, String defaultPath, Version version,
                     Collection<String> fileTypes, String docWebsite, boolean supportsDump, String dumpDirectory) {
        super(name, description, defaultPath, version, fileTypes, docWebsite);
        this.supportsDump = supportsDump;
        setDumpDirectory(dumpDirectory);
    }

    public boolean supportsDump() { return supportsDump; }
    public String getDumpDirectory() { return dumpDirectory; }

    public void setSupportsDump(boolean supportsDump) { this.supportsDump = supportsDump; }
    public final void setDumpDirectory(String dir) { this.dumpDirectory = Validate.notBlank(dir, "dumpDirectory"); }

    @Override public String getKind() { return "DEBUG"; }

    /** Attaching to a live process needs elevation. */
    @Override public IntegrityLevel requiredIntegrity() { return IntegrityLevel.HIGH; }

    @Override public List<String> buildCommand(ProcessInstance target) {
        return List.of(getDefaultPath(), "-p", String.valueOf(target.getPid()));
    }

    /** Dump command (procdump style): program -ma PID dumpDirectory/fileName */
    public List<String> buildDumpCommand(ProcessInstance target, String fileName) {
        if (!supportsDump) throw new ValidationException(getName() + " cannot create dumps");
        String f = Validate.notBlank(fileName, "fileName");
        if (!f.toLowerCase().endsWith(".dmp") || f.contains("/") || f.contains("\\") || f.contains("..")) {
            throw new ValidationException("dump file name must be a plain name ending in .dmp (got " + f + ")");
        }
        String out = Path.of(dumpDirectory).resolve(f).toString();
        return List.of(getDefaultPath(), "-ma", String.valueOf(target.getPid()), out);
    }
}
