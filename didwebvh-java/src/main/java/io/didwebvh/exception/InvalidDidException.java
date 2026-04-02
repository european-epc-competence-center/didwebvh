package io.didwebvh.exception;

/**
 * Thrown when the DID string itself is syntactically or semantically invalid.
 *
 * <p>Use this for errors in DID parsing, ABNF violations, or DID-to-HTTPS
 * transformation failures — situations where the DID identifier cannot be
 * understood before any log processing begins.
 *
 * <p>Maps to spec error code {@code invalidDid}.
 */
public class InvalidDidException extends DidWebVhException {

    public InvalidDidException(String message) {
        super(message);
    }

    public InvalidDidException(String message, Throwable cause) {
        super(message, cause);
    }
}
