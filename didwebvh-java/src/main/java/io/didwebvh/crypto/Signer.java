package io.didwebvh.crypto;

/**
 * Signs raw bytes and returns the signature bytes.
 *
 * <p>The {@code eddsa-jcs-2022} cryptosuite requires Ed25519 signatures.
 * Callers provide their own implementation backed by the key material of their choice.
 *
 * <p>{@link DataIntegrity} prepares the data-to-sign and calls this interface;
 * the implementation is responsible only for the raw signing operation.
 */
@FunctionalInterface
public interface Signer {

    /**
     * Signs the given data.
     *
     * @param data the bytes to sign
     * @return the raw signature bytes
     * @throws io.didwebvh.exception.DidWebVhException if signing fails
     */
    byte[] sign(byte[] data);
}
