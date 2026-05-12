package io.didwebvh.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An ordered sequence of {@link DidLogEntry} objects representing the full
 * did:webvh history for a single DID.
 *
 * <p>The log is append-only: the only valid mutation is appending a new entry.
 * All mutation operations in {@code operation/} return a new {@code DidLog} —
 * the caller is responsible for persisting it.
 */
public final class DidLog {

    private final List<DidLogEntry> entries;
    private final boolean parsingComplete;

    /**
     * Creates a new log from the given entries, assuming parsing was complete.
     *
     * @param entries the list of log entries
     */
    public DidLog(List<DidLogEntry> entries) {
        this(entries, true);
    }

    /**
     * Creates a new log from the given entries, with an explicit parsing-complete flag.
     *
     * @param entries         the list of log entries
     * @param parsingComplete whether all source lines were successfully parsed
     */
    public DidLog(List<DidLogEntry> entries, boolean parsingComplete) {
        this.entries = Collections.unmodifiableList(new ArrayList<>(entries));
        this.parsingComplete = parsingComplete;
    }

    /** Returns an empty {@code DidLog}. */
    public static DidLog empty() {
        return new DidLog(List.of());
    }

    /** Returns the ordered list of log entries. */
    public List<DidLogEntry> entries() {
        return entries;
    }

    /**
     * Returns {@code true} if all lines in the source JSONL were successfully parsed.
     * {@code false} means the parser stopped at a corrupt line and the log may be truncated.
     *
     * @return whether parsing completed successfully
     */
    public boolean isParsingComplete() {
        return parsingComplete;
    }

    /** Returns {@code true} if the log contains no entries. */
    public boolean isEmpty() {
        return entries.isEmpty();
    }

    /** Returns the number of entries in the log. */
    public int size() {
        return entries.size();
    }

    /**
     * Returns the most recent (last) log entry.
     *
     * @return the latest entry
     * @throws IllegalStateException if the log is empty
     */
    public DidLogEntry latest() {
        if (entries.isEmpty()) {
            throw new IllegalStateException("Log is empty");
        }
        return entries.get(entries.size() - 1);
    }

    /**
     * Returns the first (genesis) log entry.
     *
     * @return the genesis entry
     * @throws IllegalStateException if the log is empty
     */
    public DidLogEntry first() {
        if (entries.isEmpty()) {
            throw new IllegalStateException("Log is empty");
        }
        return entries.get(0);
    }

    @Override
    public String toString() {
        String label = entries.size() == 1 ? "1 entry" : entries.size() + " entries";
        StringBuilder sb = new StringBuilder("DidLog [").append(label).append("] {\n");
        for (int i = 0; i < entries.size(); i++) {
            sb.append("  [").append(i).append("] ").append(indent(entries.get(i).toString(), "      ")).append("\n");
        }
        sb.append("}");
        return sb.toString();
    }

    /** Indents every line after the first by {@code prefix}. */
    private static String indent(String s, String prefix) {
        return s.replace("\n", "\n" + prefix);
    }

    /**
     * Returns a new {@code DidLog} with {@code newEntry} appended.
     *
     * @param newEntry the entry to append
     * @return a new log containing all existing entries plus {@code newEntry}
     */
    public DidLog append(DidLogEntry newEntry) {
        List<DidLogEntry> updated = new ArrayList<>(entries);
        updated.add(newEntry);
        return new DidLog(updated);
    }
}
