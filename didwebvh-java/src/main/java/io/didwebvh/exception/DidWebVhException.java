package io.didwebvh.exception;

/**
 * Base exception for all did:webvh errors.
 *
 * <p>The spec defines two resolution error codes ({@code invalidDid}, {@code notFound}).
 * The exception <em>type</em> determines which code applies:
 * <ul>
 *   <li>{@link InvalidDidException} — DID string is syntactically/semantically invalid → {@code invalidDid}</li>
 *   <li>{@link LogValidationException} — log chain / proof / parameter validation failed → {@code invalidDid}</li>
 *   <li>{@link DidNotFoundException} — DID log or resource not found → {@code notFound}</li>
 * </ul>
 */
public class DidWebVhException extends RuntimeException {

    public DidWebVhException(String message) {
        super(message);
    }

    public DidWebVhException(String message, Throwable cause) {
        super(message, cause);
    }
}
