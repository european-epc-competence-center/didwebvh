package io.didwebvh.exception;

/**
 * Thrown when the DID log fails cryptographic or structural validation.
 *
 * <p>Examples: broken hash chain, invalid SCID, failed Data Integrity proof,
 * invalid parameter transitions (e.g. changing {@code portable} after first entry).
 */
public class LogValidationException extends DidWebVhException {

    private static final long serialVersionUID = 1L;

    /** Zero-based index of the log entry that failed validation (-1 if unknown). */
    private final int entryIndex;

    public LogValidationException(String message) {
        super("invalidDid", message);
        this.entryIndex = -1;
    }

    public LogValidationException(int entryIndex, String message) {
        super("invalidDid", String.format("Log entry %d: %s", entryIndex, message));
        this.entryIndex = entryIndex;
    }

    public int getEntryIndex() {
        return entryIndex;
    }
}
