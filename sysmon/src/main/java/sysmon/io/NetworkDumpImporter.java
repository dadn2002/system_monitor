package sysmon.io;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import sysmon.enums.HandleType;
import sysmon.enums.Protocol;
import sysmon.model.machine.Machine;
import sysmon.model.process.Connection;
import sysmon.model.process.DllModule;
import sysmon.model.process.Handle;
import sysmon.model.process.ProcessInstance;
import sysmon.util.Validate;

/**
 * Parses raw process/network dump files (such as network_data.txt and network_data_vm.txt)
 * into {@link ProcessInstance} objects for a given {@link Machine}.
 */
public class NetworkDumpImporter {

    // Matches: TCP 10.0.2.15:139 0.0.0.0:0 LISTENING [4]  OR  UDP 10.0.2.15:137 *:* N/A [4]
    private static final Pattern CONN_PATTERN = Pattern.compile(
        "^(TCP|UDP)\\s+(\\S+)\\s+(\\S+)(?:\\s+(\\S+))?(?:\\s+\\d+)?$",
        Pattern.CASE_INSENSITIVE
);

    public List<ProcessInstance> importFile(Path file, Machine machine, Instant observedAt) throws IOException {
        Validate.notNull(file, "file");
        Validate.notNull(machine, "machine");
        Validate.notNull(observedAt, "observedAt");

        List<ProcessInstance> instances = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) continue;
                ProcessInstance parsed = parseLine(line, machine, observedAt);
                if (parsed != null) {
                    instances.add(parsed);
                }
            }
        }
        return instances;
    }

    public ProcessInstance parseLine(String line, Machine machine, Instant observedAt) {
        Validate.notBlank(line, "line");
        Validate.notNull(machine, "machine");
        Validate.notNull(observedAt, "observedAt");

        List<String> fields = splitTopLevelFields(line);
        if (fields.size() < 2) {
            return null;
        }

        String name = unquoteAndClean(fields.get(0));
        if (name.isBlank()) {
            return null;
        }

        int pid;
        try {
            pid = Integer.parseInt(fields.get(1).trim());
        } catch (NumberFormatException e) {
            return null;
        }

        ProcessInstance instance = new ProcessInstance(
                pid,
                name,
                null,
                machine,
                observedAt,
                null,
                null
        );

        String dllsField = fields.size() > 2 ? fields.get(2) : "[]";
        String handlesField = fields.size() > 3 ? fields.get(3) : "[]";
        String networkField = fields.size() > 4 ? fields.get(4) : "[]";

        for (DllModule module : parseModules(dllsField)) {
            instance.addModule(module);
        }
        for (Handle handle : parseHandles(handlesField)) {
            instance.addHandle(handle);
        }
        for (Connection connection : parseConnections(networkField)) {
            instance.addConnection(connection);
        }

        return instance;
    }

    /**
     * Splits a record into top-level comma-separated fields while keeping bracketed
     * lists ([...]) and quoted strings ('...' or "...") intact.
     */
    private List<String> splitTopLevelFields(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int bracketDepth = 0;
        char quoteChar = 0;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);

            if (quoteChar != 0) {
                current.append(c);
                if (c == quoteChar && (i == 0 || line.charAt(i - 1) != '\\')) {
                    quoteChar = 0;
                }
                continue;
            }

            if (c == '\'' || c == '"') {
                quoteChar = c;
                current.append(c);
            } else if (c == '[') {
                bracketDepth++;
                current.append(c);
            } else if (c == ']') {
                bracketDepth = Math.max(0, bracketDepth - 1);
                current.append(c);
            } else if (c == ',' && bracketDepth == 0) {
                fields.add(current.toString().trim());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }

        if (current.length() > 0 || line.endsWith(",")) {
            fields.add(current.toString().trim());
        }
        return fields;
    }

    /**
     * Extracts items inside an outer [...] list, respecting quotes.
     */
    private List<String> splitListItems(String bracketedList) {
        List<String> items = new ArrayList<>();
        if (bracketedList == null) return items;

        String trimmed = bracketedList.trim();
        if (trimmed.isEmpty() || "[]".equals(trimmed)) return items;

        int start = trimmed.startsWith("[") ? 1 : 0;
        int end = trimmed.endsWith("]") ? trimmed.length() - 1 : trimmed.length();
        if (start >= end) return items;

        String inner = trimmed.substring(start, end);
        StringBuilder current = new StringBuilder();
        int depth = 0;
        char quoteChar = 0;

        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);

            if (quoteChar != 0) {
                current.append(c);
                if (c == quoteChar && (i == 0 || inner.charAt(i - 1) != '\\')) {
                    quoteChar = 0;
                }
                continue;
            }

            if (c == '\'' || c == '"') {
                quoteChar = c;
                current.append(c);
            } else if (c == '[' || c == '(') {
                depth++;
                current.append(c);
            } else if (c == ']' || c == ')') {
                depth = Math.max(0, depth - 1);
                current.append(c);
            } else if (c == ',' && depth == 0) {
                String item = current.toString().trim();
                if (!item.isEmpty()) {
                    items.add(item);
                }
                current.setLength(0);
            } else {
                current.append(c);
            }
        }

        String last = current.toString().trim();
        if (!last.isEmpty()) {
            items.add(last);
        }
        return items;
    }

    private List<DllModule> parseModules(String dllsField) {
        List<DllModule> modules = new ArrayList<>();
        for (String rawItem : splitListItems(dllsField)) {
            String cleaned = unquoteAndClean(rawItem);
            if (!cleaned.isBlank()) {
                modules.add(new DllModule(cleaned));
            }
        }
        return modules;
    }

    private List<Handle> parseHandles(String handlesField) {
        List<Handle> handles = new ArrayList<>();
        for (String rawItem : splitListItems(handlesField)) {
            String cleaned = unquoteAndClean(rawItem);
            if (cleaned.isBlank()) continue;

            // Supports formats like "File: C:\foo" or "TYPE target : detail" or plain target
            HandleType type = resolveHandleType(cleaned);
            String target = cleaned;
            String detail = null;

            int colonIdx = cleaned.indexOf(':');
            if (colonIdx > 0 && colonIdx < cleaned.length() - 1) {
                target = cleaned.substring(colonIdx + 1).trim();
                int detailSep = target.indexOf(" : ");
                if (detailSep > 0) {
                    detail = target.substring(detailSep + 3).trim();
                    target = target.substring(0, detailSep).trim();
                }
            }

            if (!target.isBlank()) {
                handles.add(new Handle(type, target, detail));
            }
        }
        return handles;
    }

    private List<Connection> parseConnections(String networkField) {
        List<Connection> connections = new ArrayList<>();
        if (networkField == null) {
            return connections;
        }

        String trimmed = networkField.trim();
        if (trimmed.isEmpty() || "[]".equals(trimmed)) {
            return connections;
        }

        for (String entry : extractBracketedEntries(trimmed)) {
            String cleaned = unquoteAndClean(entry);
            if (cleaned.isBlank()) {
                continue;
            }

            String normalized = cleaned;
            if ((cleaned.startsWith("[") && cleaned.endsWith("]")) ||
                (cleaned.startsWith("(") && cleaned.endsWith(")"))) {
                String inner = cleaned.substring(1, cleaned.length() - 1);
                List<String> parts = new ArrayList<>();
                for (String part : splitCommaRespectingQuotes(inner)) {
                    String p = unquoteAndClean(part);
                    if (!p.isBlank()) {
                        parts.add(p);
                    }
                }
                normalized = String.join(" ", parts);
            }

            Matcher m = CONN_PATTERN.matcher(normalized);
            if (m.matches()) {
                Protocol protocol = Protocol.valueOf(m.group(1).toUpperCase(Locale.ROOT));
                String localAddr = m.group(2);
                String foreignAddr = m.group(3);
                String state = m.group(4);
                connections.add(new Connection(protocol, localAddr, foreignAddr, state));
            }
        }
        return connections;
    }

    private List<String> extractBracketedEntries(String field) {
        List<String> entries = new ArrayList<>();
        String inner = field.trim();
        if (inner.startsWith("[") && inner.endsWith("]") && inner.length() >= 2) {
            inner = inner.substring(1, inner.length() - 1);
        }

        StringBuilder current = new StringBuilder();
        int depth = 0;
        char quoteChar = 0;

        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);

            if (quoteChar != 0) {
                current.append(c);
                if (c == quoteChar && (i == 0 || inner.charAt(i - 1) != '\\')) {
                    quoteChar = 0;
                }
                continue;
            }

            if (c == '\'' || c == '"') {
                quoteChar = c;
                current.append(c);
            } else if (c == '[' || c == '(') {
                if (depth > 0) {
                    current.append(c);
                }
                depth++;
                current.append(c);
            } else if (c == ']' || c == ')') {
                depth = Math.max(0, depth - 1);
                current.append(c);
                if (depth == 0) {
                    entries.add(current.toString().trim());
                    current.setLength(0);
                }
            } else if (c == ',' && depth == 0) {
                String item = current.toString().trim();
                if (!item.isEmpty()) {
                    entries.add(item);
                }
                current.setLength(0);
            } else if (depth > 0 || !Character.isWhitespace(c)) {
                current.append(c);
            }
        }

        String tail = current.toString().trim();
        if (!tail.isEmpty()) {
            entries.add(tail);
        }
        return entries;
    }

    private List<String> splitCommaRespectingQuotes(String text) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        char quoteChar = 0;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (quoteChar != 0) {
                current.append(c);
                if (c == quoteChar && (i == 0 || text.charAt(i - 1) != '\\')) {
                    quoteChar = 0;
                }
                continue;
            }

            if (c == '\'' || c == '"') {
                quoteChar = c;
                current.append(c);
            } else if (c == ',') {
                parts.add(current.toString().trim());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }

        if (current.length() > 0) {
            parts.add(current.toString().trim());
        }
        return parts;
    }

    private HandleType resolveHandleType(String entry) {
        String upper = entry.toUpperCase(Locale.ROOT);
        for (HandleType candidate : HandleType.values()) {
            if (upper.startsWith(candidate.name() + ":") || upper.startsWith(candidate.name() + " ")) {
                return candidate;
            }
        }
        // Fallback to first enum value if unprefixed
        return HandleType.values()[0];
    }

    /**
     * Removes surrounding single/double quotes, trims whitespace, and strips
     * stray trailing commas like 'ucrtbase.dll,' seen in raw dumps.
     */
    private String unquoteAndClean(String raw) {
        if (raw == null) return "";
        String s = raw.trim();
        if (s.length() >= 2 && ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith("\"") && s.endsWith("\"")))) {
            s = s.substring(1, s.length() - 1).trim();
        }
        while (s.endsWith(",")) {
            s = s.substring(0, s.length() - 1).trim();
        }
        if (s.length() >= 2 && ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith("\"") && s.endsWith("\"")))) {
            s = s.substring(1, s.length() - 1).trim();
        }
        return s;
    }
}