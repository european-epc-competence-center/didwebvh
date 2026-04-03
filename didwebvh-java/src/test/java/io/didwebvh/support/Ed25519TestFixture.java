package io.didwebvh.support;

import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import io.didwebvh.crypto.Verifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;

/**
 * Test helper that generates a fresh Ed25519 key pair together with matching
 * {@link Signer} and {@link Verifier} implementations backed by BouncyCastle.
 *
 * <p>Call {@link #generate()} in a JUnit {@code @BeforeEach} to get a fresh key pair per test.
 */
public record Ed25519TestFixture(Signer signer, Verifier verifier, String publicKeyMultibase) {

    public static Ed25519TestFixture generate() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();

        String publicKeyMultibase = Multiformats.encodeEd25519Multikey(publicKey.getEncoded());

        Signer signer = Signer.create(publicKeyMultibase, data -> {
            Ed25519Signer s = new Ed25519Signer();
            s.init(true, privateKey);
            s.update(data, 0, data.length);
            return s.generateSignature();
        });

        Verifier verifier = (signature, message, keyMultibase) -> {
            byte[] rawKey = Multiformats.decodeEd25519Multikey(keyMultibase);
            Ed25519PublicKeyParameters pubKey = new Ed25519PublicKeyParameters(rawKey, 0);
            Ed25519Signer v = new Ed25519Signer();
            v.init(false, pubKey);
            v.update(message, 0, message.length);
            return v.verifySignature(signature);
        };

        return new Ed25519TestFixture(signer, verifier, publicKeyMultibase);
    }
}
