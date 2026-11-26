package sysmon.model.tool;

import sysmon.enums.HandleType;
import sysmon.exception.ValidationException;
import sysmon.model.process.ProcessInstance;

import java.util.Collection;
import java.util.List;
import java.util.Set;

/** Tools that list open handles (handle.exe, Process Explorer...). */
public class HandleTool extends Tool {
    private Set<HandleType> handleTypes;

    public HandleTool(String name, String description, String defaultPath, Version version,
                      Collection<String> fileTypes, String docWebsite, Collection<HandleType> handleTypes) {
        super(name, description, defaultPath, version, fileTypes, docWebsite);
        setHandleTypes(handleTypes);
    }

    /** Which handle types this tool is able to report. */
    public Set<HandleType> getHandleTypes() { return handleTypes; }

    public final void setHandleTypes(Collection<HandleType> types) {
        if (types == null || types.isEmpty()) {
            throw new ValidationException("handleTypes must contain at least one type");
        }
        this.handleTypes = Set.copyOf(types);
    }

    public boolean reports(HandleType type) { return handleTypes.contains(type); }

    @Override public String getKind() { return "HANDLE"; }

    /** Same call the collector uses today: handle.exe -a -p PID */
    @Override public List<String> buildCommand(ProcessInstance target) {
        return List.of(getDefaultPath(), "-a", "-p", String.valueOf(target.getPid()));
    }
}
