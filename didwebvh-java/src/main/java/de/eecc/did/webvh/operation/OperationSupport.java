package de.eecc.did.webvh.operation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.eecc.did.webvh.DidDocument;
import de.eecc.did.webvh.crypto.DataIntegrity;
import de.eecc.did.webvh.crypto.JcsCanonicalizer;
import de.eecc.did.webvh.crypto.Multiformats;
import de.eecc.did.webvh.crypto.Signer;
import de.eecc.did.webvh.model.DidLog;
import de.eecc.did.webvh.model.DidLogEntry;
import de.eecc.did.webvh.model.Parameters;
import de.eecc.did.webvh.model.proof.DataIntegrityProof;
import de.eecc.did.webvh.util.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Shared helpers for controller operations ({@link CreateOperation}, {@link UpdateOperation},
 * {@link DeactivateOperation}): deriving effective parameters from a log, validating signing keys,
 * and building hashed/signed log entries.
 */
final class OperationSupport {

    private static final ObjectMapper MAPPER = JsonMapper.INSTANCE;

    private OperationSupport() {}

    /**
     * Walks the log from genesis to latest, merging parameters at each step to compute
     * the fully-merged effective parameter state.
     */
    static Parameters effectiveParameters(DidLog log) {
        Parameters active = null;
        for (DidLogEntry entry : log.entries()) {
            active = entry.parameters().validate(active);
        }
        return active;
    }

    /**
     * Builds a log entry with a properly computed versionId and Data Integrity proof.
     *
     * <p>The hash chain step (spec §6) is:
     * <ol>
     *   <li>Build a preliminary entry with {@code versionId = predecessorVersionId} and no proof.</li>
     *   <li>JCS-canonicalize and SHA-256-multihash to get the entry hash.</li>
     *   <li>Set {@code versionId = versionNumber + "-" + entryHash}.</li>
     *   <li>Sign the entry with the given signer and attach the proof.</li>
     * </ol>
     *
     * @param predecessorVersionId the versionId to use as the hash predecessor (SCID for genesis,
     *                             previous entry's versionId for updates)
     * @param versionNumber        the integer version number for the new entry
     * @param versionTime          the ISO-8601 UTC timestamp
     * @param parameters           the parameter delta (or full params for genesis)
     * @param state                the DID document state for this entry
     * @param signer               the signing key
     * @return the final log entry with versionId and proof attached
     */
    static DidLogEntry buildHashedAndSignedEntry(
            String predecessorVersionId,
            int versionNumber,
            String versionTime,
            Parameters parameters,
            DidDocument state,
            Signer signer) {

        DidLogEntry forHashing = new DidLogEntry(
                predecessorVersionId, versionTime, parameters, state, null);

        JsonNode hashInput = MAPPER.valueToTree(forHashing);
        String entryHash = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(hashInput));
        String versionId = versionNumber + "-" + entryHash;

        DidLogEntry entryWithVersionId = new DidLogEntry(
                versionId, versionTime, parameters, state, null);

        JsonNode documentToSign = MAPPER.valueToTree(entryWithVersionId);
        DataIntegrityProof proof = DataIntegrity.createProof(
                documentToSign,
                signer.getVerificationMethodId(),
                signer);

        return new DidLogEntry(versionId, versionTime, parameters, state, List.of(proof));
    }

    /**
     * Validates that the signer is authorized per the spec's "Authorized Keys" rules:
     * <ul>
     *   <li>No pre-rotation: signer's verification method must be listed in the active
     *       {@code updateKeys}.</li>
     *   <li>Pre-rotation active: the signer is the newly-revealed key; its hash must appear
     *       in the previous {@code nextKeyHashes}.</li>
     * </ul>
     *
     * @throws IllegalArgumentException if the signer is not authorized
     */
    static void validateSigningKeyAuthorization(Signer signer, Parameters activeParams) {
        String signerVerificationMethod = signer.getVerificationMethodId();
        String signerMultikey = Multiformats.extractMultikey(signerVerificationMethod);
        
        if (activeParams.isPreRotationActive()) {
            String signerKeyHash = Multiformats.sha256Multihash(signerMultikey.getBytes(StandardCharsets.UTF_8));
            List<String> committed = activeParams.nextKeyHashes();
            if (committed == null || !committed.contains(signerKeyHash)) {
                throw new IllegalArgumentException(
                        "Signing key '" + signerVerificationMethod + "' (multikey: " + signerMultikey
                                + ", hash: " + signerKeyHash
                                + ") was not committed in the previous 'nextKeyHashes'. "
                                + "When pre-rotation is active, you must sign with the "
                                + "newly-revealed key whose hash was pre-committed.");
            }
        } else {
            List<String> activeKeys = activeParams.updateKeys();
            if (activeKeys == null || !activeKeys.contains(signerMultikey)) {
                throw new IllegalArgumentException(
                        "Signing key '" + signerVerificationMethod + "' (multikey: " + signerMultikey
                                + ") is not in the active 'updateKeys': " + activeKeys);
            }
        }
    }
}
