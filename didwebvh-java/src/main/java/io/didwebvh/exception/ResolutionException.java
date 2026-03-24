package io.didwebvh.exception;

/**
 * Thrown when DID resolution fails (network error, missing log, HTTP error).
 *
 * <p>Corresponds to the spec error code {@code notFound} when the log cannot
 * be retrieved, or {@code invalidDid} when the retrieved log fails validation.
 */
public class ResolutionException extends DidWebVhException {

    private static final long serialVersionUID = 1L;

    public ResolutionException(String errorCode, String message) {
        super(errorCode, message);
    }

    public ResolutionException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
