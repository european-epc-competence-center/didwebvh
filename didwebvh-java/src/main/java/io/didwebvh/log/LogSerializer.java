package io.didwebvh.log;

import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;

/**
 * Serializes a did:webvh log to its JSONL wire format.
 *
 * <p>Each {@link DidLogEntry} is written as a compact (no extra whitespace) JSON
 * object followed by a newline character. This matches the spec requirement:
 * "one compact JSON object per line, {@code \n} terminated".
 *
 * @see LogParser
 */
public final class LogSerializer {

    private LogSerializer() {}

    /**
     * Serializes the full log to a JSONL string.
     *
     * @param log the log to serialize
     * @return the JSONL string ready to be written as {@code did.jsonl}
     */
    public static String serialize(DidLog log) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Serializes a single log entry to a compact JSON string (no trailing newline).
     *
     * @param entry the log entry
     * @return the compact JSON string
     */
    public static String serializeLine(DidLogEntry entry) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
