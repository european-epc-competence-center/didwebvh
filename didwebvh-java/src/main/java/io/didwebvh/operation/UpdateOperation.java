package io.didwebvh.operation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.didwebvh.DidWebVhConstants;
import io.didwebvh.api.UpdateOptions;
import io.didwebvh.api.UpdateResult;
import io.didwebvh.crypto.DataIntegrity;
import io.didwebvh.crypto.JcsCanonicalizer;
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;
import io.didwebvh.model.ResolutionMetadata;
import io.didwebvh.model.proof.DataIntegrityProof;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;

/**
 * Implements the did:webvh {@code Update} operation.
 *
 * <p>Appends a new log entry to an existing log following the spec §3.6.3 flow:
 * <ol>
 *   <li>Validate inputs and compute the fully-merged active parameter state.</li>
 *   <li>Reject if the DID is deactivated.</li>
 *   <li>Verify the signing key is authorized (spec "Authorized Keys"):
 *       without pre-rotation the signer must be in the previous {@code updateKeys};
 *       with pre-rotation the signer's key hash must be in the previous {@code nextKeyHashes}.</li>
 *   <li>Build the new effective parameters from the options; if pre-rotation is active,
 *       verify that each new {@code updateKey} hash was committed in the previous
 *       {@code nextKeyHashes} (spec §3.6.3 step 7).</li>
 *   <li>Compute the parameter delta and build the new entry with
 *       {@code versionId} = previous {@code versionId}.</li>
 *   <li>Compute the new entry hash and set {@code versionId = "{n+1}-{hash}"}.</li>
 *   <li>Generate a Data Integrity proof with the authorized signing key.</li>
 *   <li>Return the log with the new entry appended.</li>
 * </ol>
 */
public final class UpdateOperation {

    private static final Logger log = LoggerFactory.getLogger(UpdateOperation.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private UpdateOperation() {}

    /**
     * Appends an update entry to the log supplied in {@code options}.
     *
     * @param options update options (current log, new document, signer, and any parameter changes)
     * @return the result containing the updated log
     * @throws IllegalArgumentException if required options are missing or invalid
     * @throws io.didwebvh.exception.LogValidationException if the current log state is invalid for updates
     */
    public static UpdateResult update(UpdateOptions options) {
        validateOptions(options);
        log.trace("Received request to update DID log with {} entries", options.getLog().size());

        try {
            DidLog currentLog = options.getLog();
            DidLogEntry previous = currentLog.latest();

            Parameters activeParams = computeEffectiveParams(currentLog);

            if (activeParams.isDeactivated()) {
                throw new IllegalStateException("Cannot update a deactivated DID");
            }

            // Spec §6.3 step 6: verify the signer is authorized under the active key rules.
            // Without pre-rotation: signer must be in the previous (active) updateKeys.
            // With pre-rotation: signer's key hash must be in the previous nextKeyHashes
            //   (because the key being used to sign is the new key being revealed, whose
            //    hash was committed in the previous entry's nextKeyHashes).
            validateSigningKeyAuthorization(options.getSigner(), activeParams);

            Parameters newEffective = buildNewEffective(options, activeParams);

            // Spec §6.3 step 7: if pre-rotation was active, each new updateKey's hash
            // must appear in the previous nextKeyHashes.
            validatePreRotationCommitments(newEffective, activeParams);

            Parameters delta = newEffective.diff(activeParams);

            // Spec: while pre-rotation is active, updateKeys and nextKeyHashes
            // MUST be present in every log entry — even if unchanged from the
            // previous entry.  diff() strips equal fields, so we force them back in.
            // Note: this is a workaround to ensure that the updateKeys and nextKeyHashes
            // are always present in the log entry, even if they are unchanged from the
            // previous entry. Not the intention behind pre-rotation, but allowed.
            if (activeParams.isPreRotationActive()) {
                delta = new Parameters(
                        delta.method(),
                        delta.scid(),
                        delta.updateKeys() != null ? delta.updateKeys() : newEffective.updateKeys(),
                        delta.nextKeyHashes() != null ? delta.nextKeyHashes() : newEffective.nextKeyHashes(),
                        delta.portable(),
                        delta.deactivated(),
                        delta.ttl(),
                        delta.witness(),
                        delta.watchers());
            }

            String versionTime = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();

            DidLogEntry preliminaryEntry = new DidLogEntry(
                    previous.versionId(),
                    versionTime,
                    delta,
                    options.getUpdatedDocument(),
                    null);

            JsonNode hashInput = MAPPER.valueToTree(preliminaryEntry);
            String entryHash = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(hashInput));

            int newVersionNumber = previous.versionNumber() + 1;
            String versionId = newVersionNumber + "-" + entryHash;

            DidLogEntry entryWithVersionId = new DidLogEntry(
                    versionId,
                    versionTime,
                    delta,
                    options.getUpdatedDocument(),
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
                    options.getUpdatedDocument(),
                    List.of(proof));

            DidLog updatedLog = currentLog.append(finalEntry);

            String genesisTime = currentLog.first().versionTime();
            String scid = currentLog.first().parameters().scid();
            ResolutionMetadata metadata = new ResolutionMetadata(
                    versionId,
                    versionTime,
                    genesisTime,
                    versionTime,
                    scid,
                    Boolean.TRUE.equals(newEffective.portable()),
                    newEffective.isDeactivated(),
                    String.valueOf(newEffective.ttl() != null
                            ? newEffective.ttl()
                            : DidWebVhConstants.DEFAULT_TTL_SECONDS),
                    newEffective.witness(),
                    newEffective.watchers(),
                    null,
                    null);

            log.trace("Successfully updated DID log, new versionId={}", versionId);
            return new UpdateResult(
                    finalEntry.state(),
                    metadata,
                    updatedLog);
        } catch (RuntimeException e) {
            log.debug("Failed to update DID log: {}", e.getMessage());
            throw e;
        }
    }

    private static void validateOptions(UpdateOptions options) {
        Objects.requireNonNull(options.getLog(), "log is required");
        Objects.requireNonNull(options.getUpdatedDocument(), "updatedDocument is required");
        Objects.requireNonNull(options.getSigner(), "signer is required");
        if (options.getLog().isEmpty()) {
            throw new IllegalArgumentException("log must not be empty");
        }
    }

    /**
     * Walks the log from genesis to latest, merging parameters at each step to compute
     * the fully-merged effective parameter state.
     */
    private static Parameters computeEffectiveParams(DidLog log) {
        Parameters active = null;
        for (DidLogEntry entry : log.entries()) {
            active = entry.parameters().validate(active);
        }
        return active;
    }

    /**
     * Builds the new effective (fully-merged) parameter set from the update options.
     * Fields set in {@code options} override the current active values; {@code null} means inherit.
     */
    private static Parameters buildNewEffective(UpdateOptions options, Parameters active) {
        return new Parameters(
                active.method(),
                null,
                options.getUpdateKeys() != null ? options.getUpdateKeys() : active.updateKeys(),
                options.getNextKeyHashes() != null ? options.getNextKeyHashes() : active.nextKeyHashes(),
                active.portable(),
                active.deactivated(),
                active.ttl(),
                options.getWitness() != null ? options.getWitness() : active.witness(),
                options.getWatchers() != null ? options.getWatchers() : active.watchers());
    }

    /**
     * Validates that the signer is authorized to produce this update per the spec's
     * "Authorized Keys" rules:
     * <ul>
     *   <li>No pre-rotation: signer's verification method must be listed in the active
     *       (previous entry's effective) {@code updateKeys}.</li>
     *   <li>Pre-rotation active: the signer is the newly-revealed key; its hash must appear
     *       in the previous entry's {@code nextKeyHashes} (that is how it was pre-committed).</li>
     * </ul>
     *
     * @throws IllegalArgumentException if the signer is not authorized
     */
    private static void validateSigningKeyAuthorization(Signer signer, Parameters activeParams) {
        String signerKey = signer.getVerificationMethodId();
        if (activeParams.isPreRotationActive()) {
            String signerKeyHash = Multiformats.sha256Multihash(signerKey.getBytes(StandardCharsets.UTF_8));
            List<String> committed = activeParams.nextKeyHashes();
            if (committed == null || !committed.contains(signerKeyHash)) {
                throw new IllegalArgumentException(
                        "Signing key '" + signerKey + "' (hash: " + signerKeyHash
                                + ") was not committed in the previous 'nextKeyHashes'. "
                                + "When pre-rotation is active, you must sign with the "
                                + "newly-revealed key whose hash was pre-committed.");
            }
        } else {
            List<String> activeKeys = activeParams.updateKeys();
            if (activeKeys == null || !activeKeys.contains(signerKey)) {
                throw new IllegalArgumentException(
                        "Signing key '" + signerKey + "' is not in the active 'updateKeys': " + activeKeys);
            }
        }
    }

    /**
     * When pre-rotation was active on the previous entry, validates that every key in the
     * new {@code updateKeys} has its hash listed in the previous {@code nextKeyHashes}.
     * This enforces spec §6.3 step 7.
     *
     * @throws IllegalArgumentException if any new update key was not pre-committed
     */
    private static void validatePreRotationCommitments(Parameters newEffective, Parameters activeParams) {
        if (!activeParams.isPreRotationActive()) {
            return;
        }
        List<String> committed = activeParams.nextKeyHashes();
        List<String> newUpdateKeys = newEffective.updateKeys();
        if (newUpdateKeys == null || newUpdateKeys.isEmpty()) {
            throw new IllegalArgumentException(
                    "Pre-rotation is active but no 'updateKeys' provided in the update options");
        }
        for (String multikey : newUpdateKeys) {
            String hash = Multiformats.sha256Multihash(
                    multikey.getBytes(StandardCharsets.UTF_8));
            if (!committed.contains(hash)) {
                throw new IllegalArgumentException(
                        "updateKey '" + multikey + "' (hash: " + hash + ") was not committed in the previous 'nextKeyHashes'");
            }
        }
    }

}
