package sysmon.demo;

import sysmon.enums.*;
import sysmon.exception.SysmonException;
import sysmon.model.incident.*;
import sysmon.model.machine.*;
import sysmon.model.process.*;
import sysmon.model.tool.*;
import sysmon.model.user.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** Runs every business rule once and prints OK when the rule rejects (or accepts) as expected. */
public class ModelDemo {
    private static int failures = 0;

    interface Step { void run(); }

    static void expectError(String rule, Class<? extends SysmonException> type, Step step) {
        try {
            step.run();
            failures++;
            System.out.println("FAIL  " + rule + " (nothing was thrown)");
        } catch (SysmonException e) {
            boolean ok = type.isInstance(e);
            if (!ok) failures++;
            System.out.println((ok ? "OK    " : "FAIL  ") + rule + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    static void expectOk(String rule, Step step) {
        try {
            step.run();
            System.out.println("OK    " + rule);
        } catch (RuntimeException e) {
            failures++;
            System.out.println("FAIL  " + rule + " -> " + e);
        }
    }

    public static void main(String[] args) throws Exception {
        Path fake = Files.createTempFile("tool", ".exe");   // stands in for an installed tool
        fake.toFile().deleteOnExit();
        String exe = fake.toString();

        Machine pc = new Machine("LAB-PC-01", "Windows 11 23H2");
        Machine other = new Machine("LAB-PC-02", "Windows 10 22H2");

        Tool handle = new HandleTool("handle.exe", "Lists open handles", exe, new Version("5.0"),
                List.of("txt", "csv"), "https://learn.microsoft.com/sysinternals/downloads/handle",
                List.of(HandleType.PROCESS, HandleType.THREAD));
        DebugTool procdump = new DebugTool("ProcDump", "Creates process dumps", exe, new Version("11.0"),
                List.of("dmp"), "https://learn.microsoft.com/sysinternals/downloads/procdump", true, "C:\\dumps");
        NetworkTool tshark = new NetworkTool("tshark", "Packet capture", exe, new Version("4.2.1"),
                List.of("pcap", "pcapng"), "https://www.wireshark.org/docs/", "tcp port {port}");

        Analyst ana = new Analyst("ana", "hash1");
        ana.assign(pc);
        Administrator adm = new Administrator("root", "hash2", true);
        Administrator admLow = new Administrator("rootlow", "hash3", false);

        SystemProcess lsass = new SystemProcess("lsass.exe", "Local Security Authority", "C:\\Windows\\System32\\lsass.exe", true, null);
        GameProcess game = new GameProcess("game.exe", "Some game", null, "EasyAntiCheat", "Steam");
        BrowserProcess chrome = new BrowserProcess("chrome.exe", "Browser", null, "Chromium", null, 40);

        Instant now = Instant.now();
        ProcessInstance iLsass = new ProcessInstance(700, "lsass.exe", null, pc, now, null, null);
        ProcessInstance iGame = new ProcessInstance(4100, "game.exe", null, pc, now, null, null);
        ProcessInstance iChrome = new ProcessInstance(5200, "chrome.exe", null, pc, now, null, null);
        iChrome.addConnection(new Connection(Protocol.TCP, "127.0.0.1:50000", "142.250.0.1:443", "ESTABLISHED"));
        iLsass.classify(lsass);
        iGame.classify(game);

        System.out.println("== Processes ==");
        expectError("critical system process cannot be terminated", sysmon.exception.ProtectedProcessException.class,
                () -> lsass.ensureTerminable());
        expectOk("browser can be terminated", () -> chrome.ensureTerminable());

        System.out.println("== Snapshot ==");
        Snapshot snap = new Snapshot(pc, now);
        expectOk("add three instances", () -> { snap.add(iLsass); snap.add(iGame); snap.add(iChrome); });
        expectError("duplicate PID in the same snapshot", sysmon.exception.DuplicatePidException.class,
                () -> snap.add(new ProcessInstance(700, "x.exe", null, pc, now, null, null)));
        expectError("instance from another machine", sysmon.exception.ValidationException.class,
                () -> snap.add(new ProcessInstance(9, "x.exe", null, other, now, null, null)));
        System.out.println("      unclassified queue: " + snap.findUnclassified());
        System.out.println("      using local port 50000: " + snap.findByLocalPort(50000));

        System.out.println("== Tools ==");
        expectError("network tool needs a connection", sysmon.exception.NoNetworkActivityException.class,
                () -> tshark.buildCommand(iGame));
        System.out.println("      tshark command: " + tshark.buildCommand(iChrome));
        expectError("dump name with path traversal", sysmon.exception.ValidationException.class,
                () -> procdump.buildDumpCommand(iChrome, "..\\evil.dmp"));
        System.out.println("      dump command: " + procdump.buildDumpCommand(iChrome, "chrome.dmp"));

        System.out.println("== Executions ==");
        expectError("analyst cannot run elevated debug tool", sysmon.exception.InsufficientPrivilegeException.class,
                () -> new ToolExecution(procdump, iChrome, ana));
        expectError("non-elevated admin cannot run debug tool", sysmon.exception.InsufficientPrivilegeException.class,
                () -> new ToolExecution(procdump, iChrome, admLow));
        expectError("debugger on anti-cheat game", sysmon.exception.AntiCheatRiskException.class,
                () -> new ToolExecution(procdump, iGame, adm));
        expectError("analyst on machine not assigned", sysmon.exception.InsufficientPrivilegeException.class,
                () -> new ToolExecution(handle, new ProcessInstance(1, "a.exe", null, other, now, null, null), ana));
        expectError("tool not installed", sysmon.exception.ToolNotInstalledException.class, () -> {
            Tool gone = new HandleTool("ghost", "missing", "C:\\nope\\ghost.exe", new Version("1.0"),
                    List.of("txt"), "https://example.com", List.of(HandleType.FILE));
            new ToolExecution(gone, iChrome, ana);
        });
        ToolExecution run = new ToolExecution(handle, iChrome, ana);
        System.out.println("      command: " + run.getCommand());
        expectError("cannot complete before starting", sysmon.exception.InvalidStateTransitionException.class,
                () -> run.complete("out.txt"));
        run.start();
        expectError("output file type the tool does not handle", sysmon.exception.IncompatibleFileTypeException.class,
                () -> run.complete("out.pcap"));
        expectOk("complete with .txt output", () -> run.complete("out.txt"));

        System.out.println("== Incident ==");
        SystemEvent crash = new SystemEvent(pc, now, "Application Error", 1000, Severity.CRITICAL, "chrome.exe crashed", iChrome);
        Incident inc = new Incident("chrome crash", crash);
        expectError("NEW cannot jump to RESOLVED", sysmon.exception.InvalidStateTransitionException.class,
                () -> inc.moveTo(IncidentState.RESOLVED, inc.getVersion(), ana));
        expectOk("NEW -> TRIAGED", () -> inc.moveTo(IncidentState.TRIAGED, inc.getVersion(), ana));
        expectError("stale version (someone else edited)", sysmon.exception.StaleIncidentException.class,
                () -> inc.moveTo(IncidentState.INVESTIGATING, 1, ana));
        expectOk("TRIAGED -> INVESTIGATING", () -> inc.moveTo(IncidentState.INVESTIGATING, inc.getVersion(), ana));
        expectError("resolve without evidence", sysmon.exception.MissingEvidenceException.class,
                () -> inc.moveTo(IncidentState.RESOLVED, inc.getVersion(), ana));
        inc.addEvidence(run);
        expectOk("resolve with completed evidence", () -> inc.moveTo(IncidentState.RESOLVED, inc.getVersion(), ana));
        System.out.println("      " + inc + ", severity " + inc.getSeverity());

        System.out.println();
        System.out.println(failures == 0 ? "ALL RULES BEHAVE AS EXPECTED" : failures + " CHECK(S) FAILED");
        if (failures > 0) System.exit(1);
    }
}
