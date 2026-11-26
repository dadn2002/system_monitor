package sysmon.model.process;

import sysmon.enums.HandleType;
import sysmon.util.Validate;

/** One handle a process holds, as listed by handle.exe. Immutable. */
public class Handle {
    private final HandleType type;
    private final String target;
    private final String detail;

    public Handle(HandleType type, String target, String detail) {
        this.type = Validate.notNull(type, "type");
        this.target = Validate.notBlank(target, "target");
        this.detail = (detail == null || detail.isBlank()) ? null : detail.trim();
    }

    public HandleType getType() { return type; }
    public String getTarget() { return target; }
    public String getDetail() { return detail; }

    @Override public String toString() { return type + " " + target + (detail == null ? "" : " : " + detail); }
}
