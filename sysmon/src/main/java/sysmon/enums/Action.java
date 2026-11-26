package sysmon.enums;

/** Things a user may try to do; User.can(Action) decides per profile. */
public enum Action {
    VIEW,
    CLASSIFY,
    RUN_TOOL,
    MANAGE_INCIDENTS,
    TERMINATE_PROCESS,
    CREATE_DUMP,
    MANAGE_TOOLS,
    MANAGE_USERS
}
