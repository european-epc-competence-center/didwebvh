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

    public DidLog(List<DidLogEntry> entries) {
        this.entries = Collections.unmodifiableList(new ArrayList<>(entries));
    }

    public static DidLog empty() {
        return new DidLog(List.of());
    }

    public List<DidLogEntry> entries() {
        return entries;
    }

    public boolean isEmpty() {
        return entries.isEmpty();
    }

    public int size() {
        return entries.size();
    }

    /** Returns the most recent (last) log entry, or throws if empty. */
    public DidLogEntry latest() {
        if (entries.isEmpty()) {
            throw new IllegalStateException("Log is empty");
        }
        return entries.get(entries.size() - 1);
    }

    /** Returns the first (genesis) log entry, or throws if empty. */
    public DidLogEntry first() {
        if (entries.isEmpty()) {
            throw new IllegalStateException("Log is empty");
        }
        return entries.get(0);
    }

    @Override
    public String toString() {
        return "DidLog" + entries.toString();
    }

    /** Returns a new {@code DidLog} with {@code newEntry} appended. */
    public DidLog append(DidLogEntry newEntry) {
        List<DidLogEntry> updated = new ArrayList<>(entries);
        updated.add(newEntry);
        return new DidLog(updated);
    }
}
