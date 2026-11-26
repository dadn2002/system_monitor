package sysmon.model.process;

import sysmon.exception.AntiCheatRiskException;
import sysmon.model.tool.DebugTool;
import sysmon.model.tool.Tool;

/** Game executables and launchers. */
public class GameProcess extends ProcessProfile {
    private String antiCheat;
    private String launcher;

    public GameProcess(String name, String description, String path, String antiCheat, String launcher) {
        super(name, description, path);
        setAntiCheat(antiCheat);
        setLauncher(launcher);
    }

    /** Name of the anti-cheat (EasyAntiCheat, BattlEye, Vanguard...) or null when there is none. */
    public String getAntiCheat() { return antiCheat; }
    public String getLauncher() { return launcher; }

    public final void setAntiCheat(String antiCheat) {
        this.antiCheat = (antiCheat == null || antiCheat.isBlank()) ? null : antiCheat.trim();
    }
    public final void setLauncher(String launcher) {
        this.launcher = (launcher == null || launcher.isBlank()) ? null : launcher.trim();
    }

    public boolean hasAntiCheat() { return antiCheat != null; }

    @Override public String getCategory() { return "GAME"; }
    @Override public boolean canBeTerminated() { return true; }

    /** Debuggers on a game with anti-cheat can crash it or get the account banned. */
    @Override public void checkTool(Tool tool) {
        if (hasAntiCheat() && tool instanceof DebugTool) {
            throw new AntiCheatRiskException(getName(), antiCheat);
        }
    }
}
