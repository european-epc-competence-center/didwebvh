package io.didwebvh.exception;

/**
 * Base exception for all did:webvh errors.
 *
 * <p>Maps to the spec-defined error codes: {@code notFound}, {@code invalidDid}.
 * Where applicable, a {@code problemDetails} payload (RFC 9457) is included.
 */
public class DidWebVhException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Spec-defined error code (e.g. "notFound", "invalidDid"). */
    private final String errorCode;

    public DidWebVhException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public DidWebVhException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
