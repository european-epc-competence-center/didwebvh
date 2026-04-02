package io.didwebvh.log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

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

    private static final Logger log = LoggerFactory.getLogger(LogSerializer.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private LogSerializer() {}

    /**
     * Serializes the full log to a JSONL string.
     *
     * <p>Each entry occupies exactly one line. The returned string is {@code \n}-terminated
     * (i.e. the last line also ends with a newline), matching the JSONL convention.
     *
     * @param didLog the log to serialize
     * @return the JSONL string ready to be written as {@code did.jsonl}
     * @throws IllegalStateException if serialization fails
     */
    public static String serialize(DidLog didLog) {
        Objects.requireNonNull(didLog, "didLog must not be null");
        log.trace("Serializing DID log with {} entries", didLog.size());

        var sb = new StringBuilder();
        for (DidLogEntry entry : didLog.entries()) {
            sb.append(serializeLine(entry)).append('\n');
        }

        log.trace("Serialized DID log ({} entries, {} chars)", didLog.size(), sb.length());
        return sb.toString();
    }

    /**
     * Serializes a single log entry to a compact JSON string (no trailing newline).
     *
     * @param entry the log entry
     * @return the compact JSON string
     * @throws IllegalStateException if serialization fails
     */
    public static String serializeLine(DidLogEntry entry) {
        Objects.requireNonNull(entry, "entry must not be null");
        try {
            return MAPPER.writeValueAsString(entry);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize log entry: " + e.getMessage(), e);
        }
    }
}
