package io.didwebvh.crypto;

import java.util.Objects;
import java.util.function.Function;

/**
 * Holds a signing key and knows its identity.
 *
 * <p>The {@code eddsa-jcs-2022} cryptosuite requires Ed25519 signatures.
 * Callers provide their own implementation backed by the key material of their choice.
 *
 * <p>A {@code Signer} is both a signing function <em>and</em> the identifier of the key
 * it holds. The {@link #getVerificationMethodId()} is embedded in Data Integrity proofs
 * as the {@code verificationMethod} field, allowing resolvers to verify which
 * {@code updateKeys} entry authorized each log entry.
 *
 * <p>Use the {@link #create(String, Function)} factory for concise construction:
 * <pre>{@code
 * Signer signer = Signer.create(publicKeyMultibase, data -> ed25519Sign(privateKey, data));
 * }</pre>
 */
public interface Signer {

    /**
     * Signs the given data.
     *
     * @param data the bytes to sign
     * @return the raw signature bytes
     * @throws io.didwebvh.exception.DidWebVhException if signing fails
     */
    byte[] sign(byte[] data);

    /**
     * Returns the verification method identifier for the key held by this signer.
     *
     * <p>Typically the multikey-encoded public key (e.g. {@code z6Mk...}) that appears
     * in the log's {@code updateKeys} array. This value is embedded in every Data Integrity
     * proof produced by this signer.
     *
     * @return the verification method ID (never {@code null})
     */
    String getVerificationMethodId();

    /**
     * Creates a {@code Signer} from a verification method ID and a signing function.
     *
     * @param verificationMethodId the multikey-encoded public key or verification method URI
     * @param signFunction         the raw signing function ({@code data -> signature})
     * @return a new {@code Signer}
     */
    static Signer create(String verificationMethodId, Function<byte[], byte[]> signFunction) {
        Objects.requireNonNull(verificationMethodId, "verificationMethodId");
        Objects.requireNonNull(signFunction, "signFunction");
        return new Signer() {
            @Override
            public byte[] sign(byte[] data) {
                return signFunction.apply(data);
            }

            @Override
            public String getVerificationMethodId() {
                return verificationMethodId;
            }
        };
    }
}
