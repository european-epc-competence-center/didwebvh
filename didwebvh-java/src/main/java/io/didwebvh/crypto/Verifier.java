package io.didwebvh.crypto;

/**
 * Verifies a signature over a message using a public key.
 *
 * <p>The {@code eddsa-jcs-2022} cryptosuite requires Ed25519 verification.
 * The public key is provided as a multibase-encoded multikey string, as stored
 * in the {@code updateKeys} field of the log.
 *
 * <p>Callers provide their own implementation backed by the key material of their choice.
 */
@FunctionalInterface
public interface Verifier {

    /**
     * Verifies {@code signature} over {@code message} using the given public key.
     *
     * @param signature          the raw signature bytes
     * @param message            the signed message bytes
     * @param publicKeyMultibase the signer's public key as a multibase-encoded multikey string
     * @return {@code true} if the signature is valid
     * @throws io.didwebvh.exception.DidWebVhException if verification cannot be performed
     */
    boolean verify(byte[] signature, byte[] message, String publicKeyMultibase);
}
