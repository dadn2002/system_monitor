package sysmon.io;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import sysmon.model.machine.Machine;
import sysmon.model.process.ProcessInstance;

//mvn compile; java -cp target/classes sysmon.io.IoTester

public class IoTester {
    public static void main(String[] args) throws Exception {
        NetworkDumpImporter importer = new NetworkDumpImporter();
        Machine vm = new Machine("vbox-guest", "10.0.2.15"); // adjust constructor args to match your Machine class

        Path dumpFile = Path.of("../data/network_data.txt");
        List<ProcessInstance> processes = importer.importFile(dumpFile, vm, Instant.now());

        System.out.println("Imported processes: " + processes.size());
        for (ProcessInstance p : processes) {
            if (!p.getConnections().isEmpty() || !p.getModules().isEmpty()) {
                System.out.printf(
                        // "%s (PID %d) -> (count=%d) - modules=%s, (count=%d) - handles=%s, connections=%d%n",
                        "%s (PID %d) -> modules=%d, handles=%d, connections=%d%n",
                        p.getName(),
                        p.getPid(),
                        p.getModules().size(),
                        // p.getModules(),
                        p.getHandles().size(),
                        // p.getHandles(),
                        p.getConnections().size()
                );
            }
        }
    }
}