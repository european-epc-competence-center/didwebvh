package io.didwebvh.operation;

import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Shared helpers for controller operations ({@link UpdateOperation}, {@link DeactivateOperation}):
 * deriving effective parameters from a log and validating signing keys against the spec.
 */
final class OperationSupport {

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
}
