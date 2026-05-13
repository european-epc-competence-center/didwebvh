package de.eecc.did.webvh.operation;

import de.eecc.did.webvh.DidDocument;
import de.eecc.did.webvh.DidWebVhConstants;
import de.eecc.did.webvh.api.DeactivateOptions;
import de.eecc.did.webvh.api.DeactivateResult;
import de.eecc.did.webvh.model.DidLog;
import de.eecc.did.webvh.model.DidLogEntry;
import de.eecc.did.webvh.model.Parameters;
import de.eecc.did.webvh.model.DidDocumentMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

            DidDocument document = previous.state();
            String versionTime = OperationSupport.computeVersionTime(
                    options.getVersionTime(), previous.versionTime());

            int newVersionNumber = previous.versionNumber() + 1;
            DidLogEntry finalEntry = OperationSupport.buildHashedAndSignedEntry(
                    previous.versionId(),
                    newVersionNumber,
                    versionTime,
                    delta,
                    document,
                    options.getSigner());

            DidLog updatedLog = currentLog.append(finalEntry);

            String genesisTime = currentLog.first().versionTime();
            String scid = currentLog.first().parameters().scid();
            String finalVersionId = finalEntry.versionId();
            DidDocumentMetadata metadata = new DidDocumentMetadata(
                    finalVersionId,
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
                    newEffective.watchers());

            log.trace("Successfully deactivated DID log, new versionId={}", finalVersionId);
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
