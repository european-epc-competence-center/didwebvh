package de.eecc.did.webvh.witness;

import com.fasterxml.jackson.databind.node.ObjectNode;
import de.eecc.did.webvh.crypto.DataIntegrity;
import de.eecc.did.webvh.exception.LogValidationException;
import de.eecc.did.webvh.model.WitnessParameter;
import de.eecc.did.webvh.model.proof.DataIntegrityProof;
import de.eecc.did.webvh.support.Ed25519TestFixture;
import de.eecc.did.webvh.util.JsonMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Regression tests for the witness-proof forgery via {@code did:key} body/fragment mismatch
 * (SECURITY-REVIEW.md, Critical).
 *
 * <p>A witness proof's {@code verificationMethod} is {@code did:key:<body>#<fragment>}. The witness
 * <em>identity</em> counted toward the threshold is derived from the body, but the signature is
 * verified against the fragment key. A well-formed {@code did:key} DID URL always has
 * {@code body == fragment}; if that equality is not enforced, an attacker can name an honest
 * witness in the body while signing with their own key in the fragment, forging an approval the
 * honest witness never gave. The fix rejects such proofs (fail-closed) at verification time.
 */
class WitnessForgeryTest {

    /** A versionId present in the valid log (index 0 = v1). */
    private static final String VERSION_ID = "1-QmForgeryPocVersionId000000000000000000000000";

    @Test
    void attackerCannotForgeWitnessApprovalWithMismatchedDidKeyBodyAndFragment() {
        // The honest witness whose approval the attacker wants to fake. The attacker does NOT
        // hold this private key — only the public multikey, which is public information.
        Ed25519TestFixture honestWitness = Ed25519TestFixture.generate();
        String witnessDid = "did:key:" + honestWitness.publicKeyMultibase();

        // The attacker's throwaway key.
        Ed25519TestFixture attacker = Ed25519TestFixture.generate();
        String attackerMultikey = attacker.publicKeyMultibase();

        // verificationMethod: body names the honest witness, fragment names the attacker key;
        // the proof is signed with the attacker key.
        String forgedVm = witnessDid + "#" + attackerMultikey;
        ObjectNode unsecured = JsonMapper.INSTANCE.createObjectNode().put("versionId", VERSION_ID);
        DataIntegrityProof forged = DataIntegrity.createProof(unsecured, forgedVm, attacker.signer());

        WitnessProofCollection proofs = new WitnessProofCollection(List.of(
                new WitnessProofCollection.Entry(VERSION_ID, List.of(forged))));
        WitnessParameter config = new WitnessParameter(1,
                List.of(new WitnessParameter.WitnessEntry(witnessDid)));
        WitnessEpoch epoch = new WitnessEpoch(config, 1, 1);

        WitnessValidator validator = new WitnessValidator(Ed25519TestFixture.verifier());

        // The forged proof must NOT satisfy the threshold — verification must fail closed.
        assertThatThrownBy(() -> validator.verifyEpochs(
                List.of(epoch), List.of(VERSION_ID), proofs, Integer.MAX_VALUE))
                .isInstanceOf(LogValidationException.class);
    }

    @Test
    void genuineWitnessProofWithMatchingBodyAndFragmentSatisfiesThreshold() {
        // Control case: a real witness signs its own proof with a well-formed verificationMethod
        // (body == fragment). This must still pass after the fix.
        Ed25519TestFixture witness = Ed25519TestFixture.generate();
        String witnessMultikey = witness.publicKeyMultibase();
        String witnessDid = "did:key:" + witnessMultikey;
        String wellFormedVm = witnessDid + "#" + witnessMultikey;

        ObjectNode unsecured = JsonMapper.INSTANCE.createObjectNode().put("versionId", VERSION_ID);
        DataIntegrityProof genuine = DataIntegrity.createProof(unsecured, wellFormedVm, witness.signer());

        WitnessProofCollection proofs = new WitnessProofCollection(List.of(
                new WitnessProofCollection.Entry(VERSION_ID, List.of(genuine))));
        WitnessParameter config = new WitnessParameter(1,
                List.of(new WitnessParameter.WitnessEntry(witnessDid)));
        WitnessEpoch epoch = new WitnessEpoch(config, 1, 1);

        WitnessValidator validator = new WitnessValidator(Ed25519TestFixture.verifier());

        assertThatCode(() -> validator.verifyEpochs(
                List.of(epoch), List.of(VERSION_ID), proofs, Integer.MAX_VALUE))
                .doesNotThrowAnyException();
    }
}
