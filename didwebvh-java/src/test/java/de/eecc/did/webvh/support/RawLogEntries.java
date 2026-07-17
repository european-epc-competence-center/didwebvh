package de.eecc.did.webvh.support;

import com.fasterxml.jackson.databind.JsonNode;
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

import java.time.Instant;
import java.util.List;

/**
 * Builds signed log entries directly, bypassing the input guards of the controller
 * operations. This lets validator and resolver tests exercise logs that a compliant
 * controller can no longer produce through the public API — e.g. an update entry
 * whose document {@code id} does not match the DID.
 */
public final class RawLogEntries {

    private RawLogEntries() {}

    /**
     * Appends an update entry with an empty parameter delta and the given document
     * state, hashed and signed exactly like the library's own entry builder
     * ({@code OperationSupport.buildHashedAndSignedEntry}).
     */
    public static DidLog appendRawUpdate(DidLog log, DidDocument state, Signer signer) {
        DidLogEntry previous = log.latest();
        String versionTime = Instant.parse(previous.versionTime()).plusSeconds(1).toString();
        Parameters delta = new Parameters(null, null, null, null, null, null, null, null, null);

        DidLogEntry forHashing = new DidLogEntry(
                previous.versionId(), versionTime, delta, state, null);
        JsonNode hashInput = JsonMapper.INSTANCE.valueToTree(forHashing);
        String entryHash = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(hashInput));
        String versionId = (previous.versionNumber() + 1) + "-" + entryHash;

        DidLogEntry unsigned = new DidLogEntry(versionId, versionTime, delta, state, null);
        DataIntegrityProof proof = DataIntegrity.createProof(
                JsonMapper.INSTANCE.valueToTree(unsigned),
                signer.getVerificationMethodId(),
                signer);

        return log.append(new DidLogEntry(versionId, versionTime, delta, state, List.of(proof)));
    }
}
