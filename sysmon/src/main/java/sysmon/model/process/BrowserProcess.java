package sysmon.model.process;

import sysmon.util.Validate;

/** Web browsers and their child processes (chrome.exe, msedge.exe, firefox.exe...). */
public class BrowserProcess extends ProcessProfile {
    private String engine;
    private String profilePath;
    private int maxChildProcesses;

    public BrowserProcess(String name, String description, String path,
                          String engine, String profilePath, int maxChildProcesses) {
        super(name, description, path);
        setEngine(engine);
        setProfilePath(profilePath);
        setMaxChildProcesses(maxChildProcesses);
    }

    public String getEngine() { return engine; }
    public String getProfilePath() { return profilePath; }
    public int getMaxChildProcesses() { return maxChildProcesses; }

    public final void setEngine(String engine) { this.engine = Validate.notBlank(engine, "engine"); }
    public final void setProfilePath(String profilePath) {
        this.profilePath = (profilePath == null || profilePath.isBlank()) ? null : profilePath.trim();
    }
    public final void setMaxChildProcesses(int max) { this.maxChildProcesses = Validate.positive(max, "maxChildProcesses"); }

    /** True when the number of running instances is above what this browser normally spawns. */
    public boolean isOverChildLimit(int runningInstances) { return runningInstances > maxChildProcesses; }

    @Override public String getCategory() { return "BROWSER"; }
    @Override public boolean canBeTerminated() { return true; }
}
