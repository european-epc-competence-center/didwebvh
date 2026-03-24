package io.didwebvh.exception;

/**
 * Thrown when the DID string is syntactically or semantically invalid.
 *
 * <p>Corresponds to the spec error code {@code invalidDid}.
 */
public class InvalidDidException extends DidWebVhException {

    private static final long serialVersionUID = 1L;

    public InvalidDidException(String message) {
        super("invalidDid", message);
    }

    public InvalidDidException(String message, Throwable cause) {
        super("invalidDid", message, cause);
    }
}
