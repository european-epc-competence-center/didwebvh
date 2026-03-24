package io.didwebvh.log;

import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;

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

    private LogParser() {}

    /**
     * Parses a full JSONL string into a {@link DidLog}.
     *
     * @param jsonl the raw content of {@code did.jsonl}
     * @return the parsed log
     * @throws io.didwebvh.exception.DidWebVhException if any line fails to parse
     */
    public static DidLog parse(String jsonl) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Parses a single JSONL line into a {@link DidLogEntry}.
     *
     * @param line a single JSON object string
     * @return the parsed entry
     */
    public static DidLogEntry parseLine(String line) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
