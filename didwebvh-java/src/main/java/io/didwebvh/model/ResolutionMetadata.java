package io.didwebvh.model;

/**
 * Metadata about the DID resolution process itself.
 *
 * <p>This corresponds to {@code didResolutionMetadata} in the W3C DID Resolution spec.
 * It contains properties that describe the resolution process, such as error codes
 * and content type.
 *
 * @param contentType   the MIME type of the resolved document
 * @param did           the DID that was resolved
 * @param driver        the resolver implementation name
 * @param error         the error code if resolution failed
 * @param problemDetails structured problem details per RFC 9457
 */
public record ResolutionMetadata(
        String contentType,
        String did,
        String driver,
        String error,
        ProblemDetails problemDetails
) {

    private static final String W3C_ERROR_PREFIX = "https://www.w3.org/ns/did#";
    private static final String DRIVER_NAME = "didwebvh-java";

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates error metadata with an RFC 9457 problem details object.
     *
     * <p>The {@code type} in the problem details is set to the corresponding W3C
     * DID Resolution error URI (e.g. {@code https://www.w3.org/ns/did#NOT_FOUND}).
     *
     * @param errorCode spec error code ({@code "invalidDid"} or {@code "notFound"})
     * @param title     short human-readable summary
     * @param detail    longer explanation
     */
    public static ResolutionMetadata error(String errorCode, String title, String detail) {
        String type = W3C_ERROR_PREFIX + toW3cErrorType(errorCode);
        return builder()
                .error(errorCode)
                .problemDetails(new ProblemDetails(type, title, detail))
                .build();
    }

    private static String toW3cErrorType(String errorCode) {
        return switch (errorCode) {
            case "invalidDid" -> "INVALID_DID";
            case "notFound"   -> "NOT_FOUND";
            default           -> errorCode.toUpperCase().replace("-", "_");
        };
    }

    /**
     * Creates success metadata for a resolved DID.
     *
     * @param did the resolved DID string
     */
    public static ResolutionMetadata success(String did) {
        return builder()
                .contentType("application/did+ld+json")
                .did(did)
                .driver(DRIVER_NAME)
                .build();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ResolutionMetadata {\n");
        if (contentType != null) sb.append("  contentType: ").append(contentType).append("\n");
        if (did != null)         sb.append("  did:         ").append(did).append("\n");
        if (driver != null)      sb.append("  driver:      ").append(driver).append("\n");
        if (error != null)       sb.append("  error:       ").append(error).append("\n");
        if (problemDetails != null) sb.append("  problem:     ").append(problemDetails).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * An RFC 9457 problem details object for structured error reporting.
     *
     * @param type  the problem type URI
     * @param title short human-readable summary
     * @param detail longer explanation
     */
    public record ProblemDetails(
            String type,
            String title,
            String detail
    ) {}

    public static final class Builder {
        private String contentType;
        private String did;
        private String driver;
        private String error;
        private ProblemDetails problemDetails;

        private Builder() {}

        public Builder contentType(String contentType) { this.contentType = contentType; return this; }
        public Builder did(String did) { this.did = did; return this; }
        public Builder driver(String driver) { this.driver = driver; return this; }
        public Builder error(String error) { this.error = error; return this; }
        public Builder problemDetails(ProblemDetails problemDetails) { this.problemDetails = problemDetails; return this; }

        public ResolutionMetadata build() {
            return new ResolutionMetadata(contentType, did, driver, error, problemDetails);
        }
    }
}
