package sysmon.exception;

public class AntiCheatRiskException extends SysmonException {
    private static final long serialVersionUID = 1L;

    public AntiCheatRiskException(String processName, String antiCheat) {
        super("Attaching a debugger to " + processName + " is blocked: " + antiCheat
                + " anti-cheat may crash the game or ban the account");
    }
}
