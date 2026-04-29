package io.didwebvh.log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.didwebvh.DidWebVhConstants;
import io.didwebvh.crypto.DataIntegrity;
import io.didwebvh.crypto.DefaultVerifier;
import io.didwebvh.crypto.JcsCanonicalizer;
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Verifier;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;
import io.didwebvh.model.proof.DataIntegrityProof;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;

/**
 * Validates the full did:webvh log chain.
 *
 * <p>Validation walks entries in order and checks, for each entry:
 * <ol>
 *   <li>SCID derivation (first entry only): the SCID in {@code parameters.scid} must equal
 *       {@code base58btc(multihash(JCS(preliminary entry)))}.</li>
 *   <li>Entry hash chain: {@code versionId} must be {@code {number}-{hash}} where the hash is
 *       derived from the entry with proof removed and {@code versionId} set to the
 *       predecessor's {@code versionId}.</li>
 *   <li>Version number: must increment by exactly 1.</li>
 *   <li>Version time: must be a valid UTC ISO-8601 timestamp, monotonically increasing,
 *       and not in the future.</li>
 *   <li>Data Integrity proof: signature must be valid and key must be in
 *       the active {@code updateKeys}.</li>
 *   <li>Parameter transition: {@link Parameters#validate(Parameters)} must pass.</li>
 *   <li>Pre-rotation: if active, new {@code updateKeys} hashes must appear in
 *       previous {@code nextKeyHashes}.</li>
 * </ol>
 *
 * <p>Entries after the first invalid entry are also considered invalid.
 */
public final class LogValidator {

    private static final Logger log = LoggerFactory.getLogger(LogValidator.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Verifier verifier;

    /**
     * Creates a validator with the given verifier.
     *
     * @param verifier the verifier used to check Data Integrity proofs on each entry;
     *                 if {@code null}, the built-in {@link DefaultVerifier} is used
     */
    public LogValidator(Verifier verifier) {
        this.verifier = verifier != null ? verifier : DefaultVerifier.instance();
    }

    /**
     * Validates the entire log.
     *
     * @param didLog the log to validate
     * @return the number of valid entries; equals {@code log.size()} when all entries are valid
     * @throws LogValidationException on the first detected violation
     */
    public int validate(DidLog didLog) {
        log.trace("Received request to validate DID log with {} entries", didLog.size());
        if (didLog.isEmpty()) {
            throw new LogValidationException("DID log is empty");
        }

        Parameters activeParams = null;
        DidLogEntry previous = null;

        // Iterate through entries in order (genesis -> latest), validating each against the previous
        for (int i = 0; i < didLog.size(); i++) {
            DidLogEntry entry = didLog.entries().get(i);
            try {
                activeParams = validateEntry(entry, previous, activeParams);
                previous = entry;
            } catch (LogValidationException e) {
                throw new LogValidationException(
                        "Log entry " + (i + 1) + " failed validation: " + e.getMessage(), e);
            }
        }

        log.trace("Successfully validated DID log with {} entries", didLog.size());
        return didLog.size();
    }

    /**
     * Validates a single entry against the previous validated state.
     * Pass {@code null} for both {@code previous} and {@code activeParams} for the genesis entry.
     *
     * <p>Three distinct parameter objects are in play:
     * <ul>
     *   <li>{@code entry.parameters()} — the <em>delta</em> from the log (only changed fields are
     *       non-null; unchanged fields are absent/null)</li>
     *   <li>{@code activeParams} — the <em>fully-merged effective state</em> accumulated from all
     *       prior entries; always non-null after genesis in the normal validation loop</li>
     *   <li>the returned value — the new fully-merged effective state after applying this entry's
     *       delta on top of {@code activeParams}; becomes {@code activeParams} for the next call</li>
     * </ul>
     *
     * @param entry        the entry to validate
     * @param previous     the preceding validated entry, or {@code null} for the first entry
     * @param activeParams the fully-merged effective parameters from all prior entries, or {@code null} for genesis
     * @return the new fully-merged effective parameters after this entry
     * @throws LogValidationException if any check fails
     */
    public Parameters validateEntry(DidLogEntry entry, DidLogEntry previous, Parameters activeParams) {
        log.trace("Validating log entry: versionId={}", entry.versionId());

        validateVersionId(entry.versionId(), entry);
        validateVersionNumber(entry, previous);
        validateVersionTime(entry, previous);
        validateEntryHash(entry, previous, activeParams);

        if (previous == null) {
            validateScid(entry);
        }

        // entry.parameters() is the DELTA for this entry (only fields that changed; other fields are null).
        // validate() merges the delta onto activeParams (the accumulated effective state from all prior entries)
        // and returns newEffective: the new fully-merged state that becomes activeParams for the next entry.
        if (entry.parameters() == null) {
            throw new LogValidationException("Entry is missing 'parameters' field");
        }
        Parameters newEffective = entry.parameters().validate(activeParams);

        // Which updateKeys authorize (sign) this entry's proof depends on whether pre-rotation is in effect:
        //   Genesis:          no previous state → the entry's own keys bootstrap trust
        //   Pre-rotation on:  the new keys were pre-committed via nextKeyHashes; they are now revealed
        //                     and sign this entry (spec §6 pre-rotation flow)
        //   No pre-rotation:  the PREVIOUS effective keys authorized this update; the proof must verify
        //                     against those keys, not the potentially-new keys in newEffective
        List<String> activeUpdateKeys;
        if (previous == null) {
            activeUpdateKeys = newEffective.updateKeys();
        } else if (activeParams != null && activeParams.isPreRotationActive()) {
            activeUpdateKeys = newEffective.updateKeys();
        } else {
            activeUpdateKeys = activeParams.updateKeys();
        }

        // Pre-rotation check: the newly revealed updateKeys must match the hashes committed in
        // activeParams.nextKeyHashes(). activeUpdateKeys already equals newEffective.updateKeys()
        // here because the pre-rotation branch above set them to the same value.
        if (previous != null && activeParams != null && activeParams.isPreRotationActive()) {
            validatePreRotationKeys(entry, activeParams, activeUpdateKeys);
        }

        validateProofs(entry, activeUpdateKeys);

        log.trace("Entry {} validated successfully", entry.versionId());
        return newEffective;
    }

    // -------------------------------------------------------------------------
    // Per-check implementations
    // -------------------------------------------------------------------------

    /** Ensures {@code versionId} has the format {@code {number}-{hash}}. */
    private static void validateVersionId(String versionId, DidLogEntry entry) {
        if (versionId == null || !versionId.contains("-")) {
            throw new LogValidationException(
                    "versionId '" + versionId + "' is not in the expected '{n}-{hash}' format");
        }
        try {
            entry.versionNumber();
        } catch (NumberFormatException e) {
            throw new LogValidationException(
                    "versionId '" + versionId + "' has a non-integer version number prefix", e);
        }
        if (entry.entryHash().isBlank()) {
            throw new LogValidationException("versionId '" + versionId + "' has an empty entry hash");
        }
    }

     /** Ensures {@code versionNumber} is one more than the previous entry's version number. */
    private static void validateVersionNumber(DidLogEntry entry, DidLogEntry previous) {
        int expectedVersion = previous == null ? 1 : previous.versionNumber() + 1;
        if (entry.versionNumber() != expectedVersion) {
            throw new LogValidationException(
                    "Expected version number " + expectedVersion + " but got " + entry.versionNumber());
        }
    }

    /** Ensures {@code versionTime} is a valid ISO-8601 UTC timestamp and 
     * is not in the future and is not before the previous entry's version time. */
    private static void validateVersionTime(DidLogEntry entry, DidLogEntry previous) {
        if (entry.versionTime() == null || entry.versionTime().isBlank()) {
            throw new LogValidationException("Entry is missing 'versionTime'");
        }
        Instant entryTime;
        try {
            // Entry time exists and is valid format (ISO-8601 UTC)
            entryTime = Instant.parse(entry.versionTime());
        } catch (DateTimeParseException e) {
            throw new LogValidationException(
                    "versionTime '" + entry.versionTime() + "' is not a valid ISO-8601 UTC timestamp", e);
        }
        if (entryTime.isAfter(Instant.now())) {
            // Entry time from the future is not valid
            throw new LogValidationException(
                    "versionTime '" + entry.versionTime() + "' is in the future");
        }
        if (previous != null) {
            // If not checking genesis, entry time must be >= previous entry time
            Instant prevTime = Instant.parse(previous.versionTime());
            if (entryTime.isBefore(prevTime)) {
                throw new LogValidationException(
                        "versionTime '" + entry.versionTime()
                                + "' is before previous entry's versionTime '" + previous.versionTime() + "'");
            }
        }
    }

    /**
     * Verifies the entry hash chain: strips proof, sets versionId to predecessor's versionId
     * (or SCID for genesis), JCS-canonicalizes, and checks the SHA-256 multihash.
     */
    private static void validateEntryHash(DidLogEntry entry, DidLogEntry previous, Parameters prevActiveParams) {
        // The predecessor versionId for hashing is:
        // - Genesis: the SCID (which was entry.versionId before "1-hash" was appended)
        // - Later entries: previous entry's versionId
        String predecessorVersionId;
        if (previous == null) {
            // For genesis, predecessorVersionId = SCID from parameters
            // (CreateOperation set versionId = scid before computing hash)
            if (entry.parameters() == null || entry.parameters().scid() == null) {
                throw new LogValidationException("Genesis entry is missing 'parameters.scid'");
            }
            predecessorVersionId = entry.parameters().scid();
        } else {
            // For later entries, predecessorVersionId = previous entry's versionId
            predecessorVersionId = previous.versionId();
        }

        DidLogEntry forHashing = new DidLogEntry(
                predecessorVersionId,
                entry.versionTime(),
                entry.parameters(),
                entry.state(),
                null);

        try {
            // DidLogEntry -> JsonNode (for JCS canonicalization)
            JsonNode hashInput = MAPPER.valueToTree(forHashing);
            // JCS-canonicalize and multihash to recompute the entry hash
            String computedHash = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(hashInput));
            String expectedHash = entry.entryHash();
            if (!computedHash.equals(expectedHash)) {
                throw new LogValidationException(
                        "Entry hash mismatch: expected '" + expectedHash + "' but computed '" + computedHash + "'");
            }
        } catch (IllegalArgumentException e) {
            throw new LogValidationException("Failed to compute entry hash: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies the SCID of the genesis entry by reconstructing the preliminary entry
     * (replacing actual SCID with {@code {SCID}}) and recomputing the hash.
     */
    private static void validateScid(DidLogEntry genesisEntry) {
        String scid = genesisEntry.parameters() != null ? genesisEntry.parameters().scid() : null;
        if (scid == null || scid.isBlank()) {
            throw new LogValidationException("Genesis entry missing 'parameters.scid'");
        }

        try {
            // Reconstruct the preliminary entry: set versionId = "{SCID}", strip proof
            DidLogEntry withoutProof = genesisEntry.withoutProof();
            DidLogEntry preliminary = new DidLogEntry(
                    DidWebVhConstants.SCID_PLACEHOLDER,
                    withoutProof.versionTime(),
                    withoutProof.parameters(),
                    withoutProof.state(),
                    null);

            // Text-replace the real SCID with {SCID} throughout the serialized entry)
            String json = MAPPER.writeValueAsString(preliminary);
            // String for replacement reasons
            json = json.replace(scid, DidWebVhConstants.SCID_PLACEHOLDER);
            // String -> JsonNode for JCS canonicalization
            JsonNode preliminaryNode = MAPPER.readTree(json);

            String computedScid = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(preliminaryNode));
            if (!computedScid.equals(scid)) {
                throw new LogValidationException(
                        "SCID mismatch: expected '" + scid + "' but computed '" + computedScid + "'");
            }
        } catch (JsonProcessingException e) {
            throw new LogValidationException("Failed to serialize entry for SCID verification: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies that all revealed {@code updateKeys} in this entry have their hashes
     * committed in the previous entry's {@code nextKeyHashes}.
     */
    private static void validatePreRotationKeys(DidLogEntry entry, Parameters prevEffective,
                                                List<String> currentUpdateKeys) {
        List<String> committed = prevEffective.nextKeyHashes();
        if (committed == null || committed.isEmpty()) {
            return; // nothing to check
        }
        if (currentUpdateKeys == null) {
            throw new LogValidationException(
                    "Pre-rotation is active but entry has no 'updateKeys'");
        }
        for (String multikey : currentUpdateKeys) {
            String hash = Multiformats.sha256Multihash(
                    multikey.getBytes(StandardCharsets.UTF_8));
            if (!committed.contains(hash)) {
                // If the hash is not in the previous entry's nextKeyHashes, the pre-rotation is not valid
                throw new LogValidationException(
                        "updateKey '" + multikey + "' (hash: " + hash
                                + ") was not committed in previous 'nextKeyHashes'");
            }
        }
    }

    /**
     * Verifies the Data Integrity proofs on the entry.
     * Each proof's {@code verificationMethod} must be in the active {@code updateKeys}.
     */
    private void validateProofs(DidLogEntry entry, List<String> activeUpdateKeys) {
        List<DataIntegrityProof> proofs = entry.proof();
        if (proofs == null || proofs.isEmpty()) {
            throw new LogValidationException("Entry is missing required Data Integrity proof(s)");
        }

        // Serialize entry to JsonNode for proof verification (DataIntegrity strips the proof field)
        JsonNode entryNode = MAPPER.valueToTree(entry);

        for (DataIntegrityProof proof : proofs) {
            validateProofFields(proof);
            String multikey = Multiformats.extractMultikey(proof.verificationMethod());
            if (activeUpdateKeys == null || !activeUpdateKeys.contains(multikey)) {
                throw new LogValidationException(
                        "Proof verificationMethod '" + proof.verificationMethod()
                                + "' is not in active updateKeys: " + activeUpdateKeys);
            }
            DataIntegrity.verifyProof(entryNode, proof, verifier);
        }
    }

    private static void validateProofFields(DataIntegrityProof proof) {
        if (!DidWebVhConstants.PROOF_TYPE.equals(proof.type())) {
            throw new LogValidationException(
                    "Proof type must be '" + DidWebVhConstants.PROOF_TYPE + "', got '" + proof.type() + "'");
        }
        if (!DidWebVhConstants.CRYPTOSUITE.equals(proof.cryptosuite())) {
            throw new LogValidationException(
                    "Proof cryptosuite must be '" + DidWebVhConstants.CRYPTOSUITE
                            + "', got '" + proof.cryptosuite() + "'");
        }
        if (!DidWebVhConstants.PROOF_PURPOSE.equals(proof.proofPurpose())) {
            throw new LogValidationException(
                    "Proof proofPurpose must be '" + DidWebVhConstants.PROOF_PURPOSE
                            + "', got '" + proof.proofPurpose() + "'");
        }
    }
}
