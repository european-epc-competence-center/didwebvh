package io.didwebvh.exception;

/**
 * Thrown when the DID log or a resource referenced by a DID URL cannot be found.
 *
 * <p>Typical causes: HTTP 404 when fetching {@code did.jsonl}, missing witness
 * file, or a {@code versionId}/{@code versionTime} query that matches no entry.
 */
public class DidNotFoundException extends DidWebVhException {

    public DidNotFoundException(String message) {
        super(message);
    }

    public DidNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
