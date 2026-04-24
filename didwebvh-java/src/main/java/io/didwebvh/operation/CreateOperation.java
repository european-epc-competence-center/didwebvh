package io.didwebvh.operation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.didwebvh.DidWebVhConstants;
import io.didwebvh.api.CreateOptions;
import io.didwebvh.api.CreateResult;
import io.didwebvh.crypto.DataIntegrity;
import io.didwebvh.crypto.JcsCanonicalizer;
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;
import io.didwebvh.model.ResolutionMetadata;
import io.didwebvh.model.proof.DataIntegrityProof;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;

/**
 * Implements the did:webvh {@code Create} operation.
 *
 * <p>Produces a genesis log entry following the spec §6.1 flow:
 * <ol>
 *   <li>Build a preliminary log entry with {@code {SCID}} placeholders and no proof.</li>
 *   <li>Compute the SCID: {@code base58btc(multihash(JCS(preliminary_entry)))}.</li>
 *   <li>Replace all {@code {SCID}} placeholders with the real SCID.</li>
 *   <li>Compute the entry hash and set {@code versionId = "1-{entryHash}"}.</li>
 *   <li>Generate a Data Integrity proof signed by the signer's key.</li>
 *   <li>Append the proof to the entry and return a single-entry log.</li>
 * </ol>
 *
 * <p>No I/O is performed. The caller is responsible for publishing the resulting
 * {@code did.jsonl} and, if witnesses are configured, the {@code did-witness.json}.
 */
public final class CreateOperation {

    private static final Logger log = LoggerFactory.getLogger(CreateOperation.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CreateOperation() {}

    /**
     * Creates the genesis DID log entry.
     *
     * @param options creation options (domain, initial document, update keys, signer, etc.)
     * @return the result containing the DID string, resolved document, metadata, and single-entry log
     * @throws IllegalArgumentException if required options are missing or invalid
     */
    public static CreateResult create(CreateOptions options) {
        log.trace("Received request to create DID for domain: {}", options.getDomain());

        validateOptions(options);

        try {
            // Build preliminary log entry with {SCID} placeholders and no proof
            String versionTime = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();

            Parameters parameters = new Parameters(
                    DidWebVhConstants.METHOD_V1_0,
                    DidWebVhConstants.SCID_PLACEHOLDER,
                    List.copyOf(options.getUpdateKeys()),
                    hasContent(options.getNextKeyHashes()) ? List.copyOf(options.getNextKeyHashes()) : null,
                    options.isPortable() ? Boolean.TRUE : null,
                    null,
                    null,
                    options.getWitness(),
                    hasContent(options.getWatchers()) ? List.copyOf(options.getWatchers()) : null);

            DidLogEntry preliminaryEntry = new DidLogEntry(
                    DidWebVhConstants.SCID_PLACEHOLDER,
                    versionTime,
                    parameters,
                    options.getInitialDocument(),
                    null);

            // Compute SCID = base58btc(multihash(SHA-256(JCS(preliminary_entry))))
            JsonNode preliminaryJson = MAPPER.valueToTree(preliminaryEntry);
            String scid = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(preliminaryJson));

            // Text-replace all {SCID} placeholders with the real SCID
            DidLogEntry scidEntry = replaceScidPlaceholder(preliminaryEntry, scid);
            String did = DidWebVhConstants.DID_METHOD_PREFIX + scid + ":" + options.getDomain();

            // Compute entry hash; for the first entry the predecessor versionId is the SCID itself,
            // which is already the versionId after placeholder replacement
            JsonNode hashInput = MAPPER.valueToTree(scidEntry);
            String entryHash = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(hashInput));
            String versionId = "1-" + entryHash;

            DidLogEntry entryWithVersionId = new DidLogEntry(
                    versionId,
                    scidEntry.versionTime(),
                    scidEntry.parameters(),
                    scidEntry.state(),
                    null);

            // Create Data Integrity proof signed by the signer's key
            JsonNode documentToSign = MAPPER.valueToTree(entryWithVersionId);
            DataIntegrityProof proof = DataIntegrity.createProof(
                    documentToSign,
                    options.getSigner().getVerificationMethodId(),
                    options.getSigner());

            DidLogEntry finalEntry = new DidLogEntry(
                    versionId,
                    scidEntry.versionTime(),
                    scidEntry.parameters(),
                    scidEntry.state(),
                    List.of(proof));

            DidLog didLog = DidLog.empty().append(finalEntry);

            ResolutionMetadata metadata = new ResolutionMetadata(
                    versionId,
                    1,
                    versionTime,
                    versionTime,
                    versionTime,
                    scid,
                    options.isPortable(),
                    false,
                    String.valueOf(DidWebVhConstants.DEFAULT_TTL_SECONDS),
                    options.getWitness(),
                    options.getWatchers(),
                    null,
                    null);

            log.trace("Successfully created DID: {}", did);
            return new CreateResult(did, finalEntry.state(), metadata, didLog);
        } catch (RuntimeException e) {
            log.debug("Failed to create DID for domain {}: {}", options.getDomain(), e.getMessage());
            throw e;
        }
    }

    private static void validateOptions(CreateOptions options) {
        Objects.requireNonNull(options.getDomain(), "domain is required");
        Objects.requireNonNull(options.getInitialDocument(), "initialDocument is required");
        Objects.requireNonNull(options.getUpdateKeys(), "updateKeys is required");
        Objects.requireNonNull(options.getSigner(), "signer is required");
        if (options.getUpdateKeys().isEmpty()) {
            throw new IllegalArgumentException("updateKeys must not be empty");
        }
    }

    /**
     * Serializes the entry to JSON, text-replaces all {@code {SCID}} occurrences
     * with the real SCID, and parses back — exactly as specified by the spec.
     */
    private static DidLogEntry replaceScidPlaceholder(DidLogEntry entry, String scid) {
        try {
            String json = MAPPER.writeValueAsString(entry);
            json = json.replace(DidWebVhConstants.SCID_PLACEHOLDER, scid);
            return MAPPER.readValue(json, DidLogEntry.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to replace SCID placeholder", e);
        }
    }

    private static boolean hasContent(List<?> list) {
        return list != null && !list.isEmpty();
    }
}
