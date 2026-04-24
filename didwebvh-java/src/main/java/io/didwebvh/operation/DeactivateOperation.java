package io.didwebvh.operation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.didwebvh.DidWebVhConstants;
import io.didwebvh.api.DeactivateOptions;
import io.didwebvh.api.DeactivateResult;
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
 * Implements the did:webvh deactivate (revoke) operation.
 *
 * <p>Aligns with spec §6.4 / v1.0: append an entry whose parameters include
 * {@code deactivated: true} and {@code updateKeys: []}, while keeping the
 * previous entry's DID document as {@code state} (same approach as didwebvh-ts
 * {@code deactivateDID} and didwebvh-rs {@code deactivate} / {@code do_deactivate}
 * final entry).
 *
 * <p>If pre-rotation is active ({@code nextKeyHashes} non-empty), the spec requires
 * clearing it before emptying {@code updateKeys}; this library does not auto-append
 * an intermediate entry (unlike didwebvh-rs {@code update_did(deactivate: true)}).
 * Call {@link UpdateOperation} first to set {@code nextKeyHashes: []} with a
 * proper key reveal, then call deactivate.
 */
public final class DeactivateOperation {

    private static final Logger log = LoggerFactory.getLogger(DeactivateOperation.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private DeactivateOperation() {}

    /**
     * Appends a deactivation entry to the log supplied in {@code options}.
     *
     * @param options deactivation options (current log and signing key)
     * @return the result containing the updated log with the deactivation entry
     * @throws IllegalArgumentException if required options are missing or invalid
     * @throws IllegalStateException if the DID is already deactivated or pre-rotation is still active
     */
    public static DeactivateResult deactivate(DeactivateOptions options) {
        validateOptions(options);
        log.trace("Received request to deactivate DID log with {} entries", options.getLog().size());

        try {
            DidLog currentLog = options.getLog();
            DidLogEntry previous = currentLog.latest();

            Parameters activeParams = OperationSupport.effectiveParameters(currentLog);

            if (activeParams.isDeactivated()) {
                throw new IllegalStateException("Cannot deactivate: DID is already deactivated");
            }
            if (activeParams.isPreRotationActive()) {
                throw new IllegalStateException(
                        "Cannot deactivate while pre-rotation is active: first append an update that sets "
                                + "nextKeyHashes to [] (and reveals the committed keys), then deactivate");
            }

            OperationSupport.validateSigningKeyAuthorization(options.getSigner(), activeParams);

            Parameters newEffective = deactivatedEffectiveParameters(activeParams);
            Parameters delta = newEffective.diff(activeParams);

            JsonNode document = previous.state();
            String versionTime = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();

            DidLogEntry preliminaryEntry = new DidLogEntry(
                    previous.versionId(),
                    versionTime,
                    delta,
                    document,
                    null);

            JsonNode hashInput = MAPPER.valueToTree(preliminaryEntry);
            String entryHash = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(hashInput));

            int newVersionNumber = previous.versionNumber() + 1;
            String versionId = newVersionNumber + "-" + entryHash;

            DidLogEntry entryWithVersionId = new DidLogEntry(
                    versionId,
                    versionTime,
                    delta,
                    document,
                    null);

            JsonNode documentToSign = MAPPER.valueToTree(entryWithVersionId);
            DataIntegrityProof proof = DataIntegrity.createProof(
                    documentToSign,
                    options.getSigner().getVerificationMethodId(),
                    options.getSigner());

            DidLogEntry finalEntry = new DidLogEntry(
                    versionId,
                    versionTime,
                    delta,
                    document,
                    List.of(proof));

            DidLog updatedLog = currentLog.append(finalEntry);

            String genesisTime = currentLog.first().versionTime();
            String scid = currentLog.first().parameters().scid();
            ResolutionMetadata metadata = new ResolutionMetadata(
                    versionId,
                    finalEntry.versionNumber(),
                    versionTime,
                    genesisTime,
                    versionTime,
                    scid,
                    Boolean.TRUE.equals(newEffective.portable()),
                    true,
                    String.valueOf(newEffective.ttl() != null
                            ? newEffective.ttl()
                            : DidWebVhConstants.DEFAULT_TTL_SECONDS),
                    newEffective.witness(),
                    newEffective.watchers(),
                    null,
                    null);

            log.trace("Successfully deactivated DID log, new versionId={}", versionId);
            return new DeactivateResult(metadata, updatedLog);
        } catch (RuntimeException e) {
            log.debug("Failed to deactivate DID log: {}", e.getMessage());
            throw e;
        }
    }

    private static void validateOptions(DeactivateOptions options) {
        Objects.requireNonNull(options.getLog(), "log is required");
        Objects.requireNonNull(options.getSigner(), "signer is required");
        if (options.getLog().isEmpty()) {
            throw new IllegalArgumentException("log must not be empty");
        }
    }

    /**
     * Full effective parameter set after deactivation: empty {@code updateKeys},
     * {@code deactivated true}, no pre-rotation; other fields inherited from current active state.
     */
    private static Parameters deactivatedEffectiveParameters(Parameters active) {
        return new Parameters(
                active.method(),
                null,
                List.of(),
                List.of(),
                active.portable(),
                Boolean.TRUE,
                active.ttl(),
                active.witness(),
                active.watchers());
    }
}
