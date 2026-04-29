package io.didwebvh.crypto;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * A built-in verifier for the standard {@code eddsa-jcs-2022} cryptosuite.
 *
 * <p>Decodes the public key from a multibase-encoded multikey string and
 * verifies the signature using Bouncy Castle's Ed25519 implementation.
 * This is the default verifier used when the caller does not supply a
 * custom {@link Verifier} in {@link io.didwebvh.api.ResolveOptions}.
 *
 * <p>The verifier is stateless and thread-safe; use {@link #instance()} to
 * obtain the singleton.
 */
public final class DefaultVerifier implements Verifier {

    private static final DefaultVerifier INSTANCE = new DefaultVerifier();

    private DefaultVerifier() {}

    /**
     * Returns the singleton default verifier.
     */
    public static DefaultVerifier instance() {
        return INSTANCE;
    }

    @Override
    public boolean verify(byte[] signature, byte[] message, String publicKeyMultibase) {
        byte[] rawKey = Multiformats.decodeEd25519Multikey(publicKeyMultibase);
        Ed25519PublicKeyParameters pubKey = new Ed25519PublicKeyParameters(rawKey, 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, pubKey);
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }
}
