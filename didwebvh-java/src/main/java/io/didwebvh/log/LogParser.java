package io.didwebvh.log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Parses a did:webvh log from its JSONL (JSON Lines) wire format.
 *
 * <p>Each line of the {@code did.jsonl} file is an independent JSON object
 * representing one {@link DidLogEntry}. Lines are separated by {@code \n}.
 * No trailing whitespace or blank lines should be present.
 *
 * @see LogSerializer
 */
public final class LogParser {

    private static final Logger log = LoggerFactory.getLogger(LogParser.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private LogParser() {}

    /**
     * Parses a full JSONL string into a {@link DidLog}.
     *
     * <p>Blank lines (empty or whitespace-only) are silently skipped to tolerate
     * trailing newlines, which are common in JSONL files.
     *
     * @param jsonl the raw content of {@code did.jsonl}
     * @return the parsed log (may be empty if the input contains no non-blank lines)
     * @throws LogValidationException if any non-blank line fails to parse
     */
    public static DidLog parse(String jsonl) {
        Objects.requireNonNull(jsonl, "jsonl must not be null");
        log.trace("Parsing DID log ({} chars)", jsonl.length());

        String[] lines = jsonl.split("\n", -1);
        List<DidLogEntry> entries = new ArrayList<>();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].strip();
            if (line.isEmpty()) {
                continue;
            }
            try {
                entries.add(parseLine(line));
            } catch (LogValidationException e) {
                throw new LogValidationException(
                        "Failed to parse log entry at line " + (i + 1) + ": " + e.getMessage(), e);
            }
        }

        log.trace("Parsed DID log with {} entries", entries.size());
        return new DidLog(entries);
    }

    /**
     * Parses a single JSONL line into a {@link DidLogEntry}.
     *
     * @param line a single JSON object string (must not be null or blank)
     * @return the parsed entry
     * @throws LogValidationException if the line is not valid JSON or cannot be mapped to a {@link DidLogEntry}
     */
    public static DidLogEntry parseLine(String line) {
        Objects.requireNonNull(line, "line must not be null");
        try {
            return MAPPER.readValue(line, DidLogEntry.class);
        } catch (JsonProcessingException e) {
            throw new LogValidationException("Failed to parse log entry: " + e.getMessage(), e);
        }
    }
}
