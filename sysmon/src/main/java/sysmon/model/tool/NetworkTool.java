package sysmon.model.tool;

import sysmon.exception.NoNetworkActivityException;
import sysmon.exception.ValidationException;
import sysmon.model.process.Connection;
import sysmon.model.process.ProcessInstance;

import java.util.Collection;
import java.util.List;

/** Network capture and inspection tools (Wireshark/tshark, TCPView...). */
public class NetworkTool extends Tool {
    private static final String PLACEHOLDER = "{port}";
    private String captureFilterTemplate;

    /** @param captureFilterTemplate must contain {port}, e.g. "tcp port {port}" */
    public NetworkTool(String name, String description, String defaultPath, Version version,
                       Collection<String> fileTypes, String docWebsite, String captureFilterTemplate) {
        super(name, description, defaultPath, version, fileTypes, docWebsite);
        setCaptureFilterTemplate(captureFilterTemplate);
    }

    public String getCaptureFilterTemplate() { return captureFilterTemplate; }

    public final void setCaptureFilterTemplate(String template) {
        if (template == null || !template.contains(PLACEHOLDER)) {
            throw new ValidationException("captureFilterTemplate must contain " + PLACEHOLDER);
        }
        this.captureFilterTemplate = template;
    }

    @Override public String getKind() { return "NETWORK"; }

    /** Needs at least one connection with a real local port, otherwise there is nothing to capture. */
    @Override public List<String> buildCommand(ProcessInstance target) {
        int port = target.getConnections().stream()
                .mapToInt(Connection::getLocalPort)
                .filter(p -> p > 0)
                .findFirst()
                .orElseThrow(() -> new NoNetworkActivityException(target.getName(), target.getPid()));
        String filter = captureFilterTemplate.replace(PLACEHOLDER, String.valueOf(port));
        return List.of(getDefaultPath(), "-f", filter);
    }
}
