package io.didwebvh;

/**
 * Cross-cutting constants used throughout the did:webvh implementation.
 *
 * <p>These values are defined by the did:webvh specification v1.0.
 * See: <a href="https://identity.foundation/didwebvh/v1.0/">did:webvh spec</a>
 */
public final class DidWebVhConstants {

    /** Placeholder string used in preliminary log entries before the SCID is computed. */
    public static final String SCID_PLACEHOLDER = "{SCID}";

    /** The method version string for did:webvh v1.0. */
    public static final String METHOD_V1_0 = "did:webvh:1.0";

    /** The DID method prefix. */
    public static final String DID_METHOD_PREFIX = "did:webvh:";

    /** The cryptosuite required by the spec for Data Integrity proofs. */
    public static final String CRYPTOSUITE = "eddsa-jcs-2022";

    /** The proof type for Data Integrity proofs. */
    public static final String PROOF_TYPE = "DataIntegrityProof";

    /** The proof purpose used for controller update proofs. */
    public static final String PROOF_PURPOSE = "assertionMethod";

    /** The content-type for the DID log file. */
    public static final String CONTENT_TYPE_JSONL = "text/jsonl";

    /** The filename for the DID log. */
    public static final String DID_LOG_FILENAME = "did.jsonl";

    /** The filename for the witness proof file. */
    public static final String WITNESS_FILENAME = "did-witness.json";

    /** The well-known path used when the DID has no path segment. */
    public static final String WELL_KNOWN_PATH = ".well-known";

    /** Default TTL in seconds (1 hour), as per spec. */
    public static final int DEFAULT_TTL_SECONDS = 3600;

    /** Multibase prefix character for base58btc encoding. */
    public static final char MULTIBASE_BASE58BTC_PREFIX = 'z';

    private DidWebVhConstants() {
        // utility class
    }
}
