package io.didwebvh.crypto;

import io.didwebvh.DidWebVhConstants;
import io.ipfs.multibase.Multibase;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Utilities for multibase encoding/decoding and multihash construction.
 *
 * <p>The did:webvh spec v1.0 requires:
 * <ul>
 *   <li>Encoding: base58btc (multibase prefix {@code z})</li>
 *   <li>Hash format: multihash with SHA-256 varint prefix {@code 0x1220}</li>
 * </ul>
 *
 * @see <a href="https://github.com/multiformats/multibase">Multibase</a>
 * @see <a href="https://github.com/multiformats/multihash">Multihash</a>
 */
public final class Multiformats {

    private Multiformats() {}

    /**
     * Encodes {@code bytes} as a base58btc multibase string (prefix {@code z}).
     *
     * @param bytes the raw bytes to encode
     * @return the multibase-encoded string including the {@code z} prefix
     */
    public static String encodeBase58btc(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        return Multibase.encode(Multibase.Base.Base58BTC, bytes);
    }

    /**
     * Decodes a base58btc multibase string (strips the {@code z} prefix).
     *
     * @param multibase the multibase string (must start with {@code z})
     * @return the decoded raw bytes
     * @throws IllegalArgumentException if the prefix is not {@code z} or the payload is invalid
     */
    public static byte[] decodeBase58btc(String multibase) {
        Objects.requireNonNull(multibase, "multibase");
        if (multibase.isEmpty()) {
            throw new IllegalArgumentException("Multibase string must be non-empty");
        }
        if (multibase.charAt(0) != DidWebVhConstants.MULTIBASE_BASE58BTC_PREFIX) {
            throw new IllegalArgumentException(
                    "Expected base58btc multibase (prefix 'z'), got prefix '" + multibase.charAt(0) + "'");
        }
        try {
            return Multibase.decode(multibase);
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid multibase base58btc payload", e);
        }
    }

    /**
     * Wraps {@code hashBytes} in a SHA-256 multihash envelope ({@code 0x12 0x20} prefix).
     *
     * @param hashBytes a raw 32-byte SHA-256 digest
     * @return the multihash-prefixed byte array (34 bytes total)
     * @throws IllegalArgumentException if {@code hashBytes} is not exactly 32 bytes
     */
    public static byte[] wrapSha256Multihash(byte[] hashBytes) {
        Objects.requireNonNull(hashBytes, "hashBytes");
        if (hashBytes.length != 32) {
            throw new IllegalArgumentException("Expected 32-byte SHA-256 digest, got " + hashBytes.length + " bytes");
        }
        byte[] out = new byte[34];
        out[0] = DidWebVhConstants.MULTIHASH_SHA2_256_CODE;
        out[1] = DidWebVhConstants.MULTIHASH_SHA2_256_DIGEST_LENGTH;
        System.arraycopy(hashBytes, 0, out, 2, 32);
        return out;
    }

    /**
     * Computes {@code base58btc(multihash(sha256(input)))} — the canonical hash
     * representation used throughout the spec for SCIDs and entry hashes.
     *
     * @param input the bytes to hash
     * @return the encoded multihash string with {@code z} prefix
     */
    public static String sha256Multihash(byte[] input) {
        Objects.requireNonNull(input, "input");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input);
            return encodeBase58btc(wrapSha256Multihash(digest));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available in this JVM", e);
        }
    }
}
