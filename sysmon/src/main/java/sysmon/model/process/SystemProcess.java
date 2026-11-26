package sysmon.model.process;

/** Windows system components (lsass.exe, csrss.exe, svchost.exe...). */
public class SystemProcess extends ProcessProfile {
    private boolean critical;
    private String owningService;

    public SystemProcess(String name, String description, String path, boolean critical, String owningService) {
        super(name, description, path);
        this.critical = critical;
        setOwningService(owningService);
    }

    public boolean isCritical() { return critical; }
    public String getOwningService() { return owningService; }

    public void setCritical(boolean critical) { this.critical = critical; }
    public final void setOwningService(String owningService) {
        this.owningService = (owningService == null || owningService.isBlank()) ? null : owningService.trim();
    }

    @Override public String getCategory() { return "SYSTEM"; }

    /** Killing a critical system process can crash or reboot the machine. */
    @Override public boolean canBeTerminated() { return !critical; }
}
