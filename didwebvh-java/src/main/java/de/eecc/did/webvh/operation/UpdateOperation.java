package de.eecc.did.webvh.operation;

import de.eecc.did.webvh.DidDocument;
import de.eecc.did.webvh.DidWebVhConstants;
import de.eecc.did.webvh.api.UpdateOptions;
import de.eecc.did.webvh.api.UpdateResult;
import de.eecc.did.webvh.crypto.Multiformats;
import de.eecc.did.webvh.model.DidLog;
import de.eecc.did.webvh.model.DidLogEntry;
import de.eecc.did.webvh.model.Parameters;
import de.eecc.did.webvh.model.DidDocumentMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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

    private UpdateOperation() {}

    /**
     * Appends an update entry to the log supplied in {@code options}.
     *
     * @param options update options (current log, new document, signer, and any parameter changes)
     * @return the result containing the updated log
     * @throws IllegalArgumentException if required options are missing or invalid
     * @throws de.eecc.did.webvh.exception.LogValidationException if the current log state is invalid for updates
     */
    public static UpdateResult update(UpdateOptions options) {
        validateOptions(options);
        log.trace("Received request to update DID log with {} entries", options.getLog().size());

        try {
            DidLog currentLog = options.getLog();
            DidLogEntry previous = currentLog.latest();

            Parameters activeParams = OperationSupport.effectiveParameters(currentLog);

            if (activeParams.isDeactivated()) {
                throw new IllegalStateException("Cannot update a deactivated DID");
            }

            // Spec §6.3 step 6: verify the signer is authorized under the active key rules.
            // Without pre-rotation: signer must be in the previous (active) updateKeys.
            // With pre-rotation: signer's key hash must be in the previous nextKeyHashes
            //   (because the key being used to sign is the new key being revealed, whose
            //    hash was committed in the previous entry's nextKeyHashes).
            OperationSupport.validateSigningKeyAuthorization(options.getSigner(), activeParams);

            Parameters newEffective = buildNewEffective(options, activeParams);

            // Spec §6.3 step 7: if pre-rotation was active, each new updateKey's hash
            // must appear in the previous nextKeyHashes.
            validatePreRotationCommitments(newEffective, activeParams);

            Parameters delta = newEffective.diff(activeParams);

            // Spec §DID Portability: if a new domain is supplied, rewrite the document's
            // id/controller to the new DID and append the previous DID to alsoKnownAs.
            DidDocument documentToWrite = applyPortableMoveIfRequested(
                    options, previous, currentLog, activeParams);

            String versionTime = OperationSupport.computeVersionTime(
                    options.getVersionTime(), previous.versionTime());

            int newVersionNumber = previous.versionNumber() + 1;
            DidLogEntry finalEntry = OperationSupport.buildHashedAndSignedEntry(
                    previous.versionId(),
                    newVersionNumber,
                    versionTime,
                    delta,
                    documentToWrite,
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
                    newEffective.isDeactivated(),
                    String.valueOf(newEffective.ttl() != null
                            ? newEffective.ttl()
                            : DidWebVhConstants.DEFAULT_TTL_SECONDS),
                    newEffective.witness(),
                    newEffective.watchers());

            log.trace("Successfully updated DID log, new versionId={}", finalVersionId);
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
                options.getTtl() != null ? options.getTtl() : active.ttl(),
                options.getWitness() != null ? options.getWitness() : active.witness(),
                options.getWatchers() != null ? options.getWatchers() : active.watchers());
    }

    /**
     * If {@link UpdateOptions#getDomain()} is set, returns a copy of the supplied document
     * with its {@code id} and {@code controller} rewritten to the new DID
     * ({@code did:webvh:{SCID}:{domain}}) and the previous DID prepended to {@code alsoKnownAs}.
     * Otherwise returns the supplied document unchanged.
     *
     * @throws IllegalStateException if the DID is not portable (genesis must have {@code portable: true})
     */
    private static DidDocument applyPortableMoveIfRequested(
            UpdateOptions options,
            DidLogEntry previous,
            DidLog currentLog,
            Parameters activeParams) {

        String newDomain = options.getDomain();
        if (newDomain == null) {
            return options.getUpdatedDocument();
        }

        if (!Boolean.TRUE.equals(activeParams.portable())) {
            throw new IllegalStateException(
                    "Cannot move DID to domain '" + newDomain + "': the DID is not portable "
                            + "(genesis entry must have parameters.portable=true).");
        }

        String scid = currentLog.first().parameters().scid();
        if (scid == null || scid.isBlank()) {
            throw new IllegalStateException("Cannot move DID: genesis entry has no SCID.");
        }

        String previousDid = previous.state().getString("id");
        if (previousDid == null || previousDid.isBlank()) {
            throw new IllegalStateException("Cannot move DID: previous entry has no document id.");
        }

        String newDid = "did:webvh:" + scid + ":" + newDomain;

        DidDocument supplied = options.getUpdatedDocument();
        DidDocument.Builder builder = supplied.toBuilder()
                .setString("id", newDid);
        if (supplied.has("controller")) {
            builder.setString("controller", newDid);
        }

        List<String> existingAka = supplied.getStrings("alsoKnownAs");
        if (!existingAka.contains(previousDid)) {
            List<String> updatedAka = new ArrayList<>(existingAka.size() + 1);
            updatedAka.add(previousDid);
            updatedAka.addAll(existingAka);
            builder.setStrings("alsoKnownAs", updatedAka);
        }

        return builder.build();
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
