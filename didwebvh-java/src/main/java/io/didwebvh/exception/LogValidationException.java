package io.didwebvh.exception;

/**
 * Thrown when the DID log fails structural, cryptographic, or parameter validation.
 *
 * <p>Covers: malformed JSONL entries, broken hash chain, invalid SCID,
 * failed Data Integrity proof, invalid parameter transitions, etc.
 */
public class LogValidationException extends DidWebVhException {

    private static final long serialVersionUID = 1L;

    public LogValidationException(String message) {
        super(message);
    }

    public LogValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
