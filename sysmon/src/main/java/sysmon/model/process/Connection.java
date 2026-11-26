package sysmon.model.process;

import sysmon.enums.Protocol;
import sysmon.util.Validate;

/** One netstat row for a process (the "ports" of a process). Immutable. */
public class Connection {
    private final Protocol protocol;
    private final String localAddress;
    private final String foreignAddress;
    private final String state;

    public Connection(Protocol protocol, String localAddress, String foreignAddress, String state) {
        this.protocol = Validate.notNull(protocol, "protocol");
        this.localAddress = Validate.notBlank(localAddress, "localAddress");
        this.foreignAddress = Validate.notBlank(foreignAddress, "foreignAddress");
        this.state = (state == null || state.isBlank()) ? "N/A" : state.trim();
    }

    public Protocol getProtocol() { return protocol; }
    public String getLocalAddress() { return localAddress; }
    public String getForeignAddress() { return foreignAddress; }
    public String getState() { return state; }

    public int getLocalPort() { return portOf(localAddress); }
    public int getForeignPort() { return portOf(foreignAddress); }

    /** Works for "127.0.0.1:80" and "[::1]:443". Returns -1 for "*:*". */
    private static int portOf(String address) {
        int i = address.lastIndexOf(':');
        if (i < 0 || i == address.length() - 1) return -1;
        try {
            return Integer.parseInt(address.substring(i + 1));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    @Override public String toString() { return protocol + " " + localAddress + " -> " + foreignAddress + " " + state; }
}
