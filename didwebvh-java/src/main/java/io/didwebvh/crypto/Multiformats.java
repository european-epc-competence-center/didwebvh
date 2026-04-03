package io.didwebvh.crypto;

import io.didwebvh.DidWebVhConstants;
import io.ipfs.multibase.Multibase;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Utilities for base58btc encoding, multibase encoding, and multihash construction.
 *
 * <p>The did:webvh spec uses two distinct base58btc encoding conventions:
 * <ul>
 *   <li><b>Raw base58btc</b> (no prefix) — for SCID, entry hashes, {@code nextKeyHashes}.
 *       These strings start with {@code Qm} for SHA-256 multihash.</li>
 *   <li><b>Multibase base58btc</b> ({@code z} prefix) — for {@code proofValue} and
 *       multikey-encoded public keys ({@code updateKeys}). Follows the
 *       <a href="https://github.com/multiformats/multibase">multibase</a> convention.</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-msporny-base58-03">base58btc (draft-msporny-base58-03)</a>
 * @see <a href="https://github.com/multiformats/multihash">Multihash</a>
 */
public final class Multiformats {

    /** Multicodec prefix for Ed25519 public keys: {@code [0xed, 0x01]}. */
    static final byte[] ED25519_MULTICODEC_PREFIX = {(byte) 0xed, (byte) 0x01};

    private Multiformats() {}

    // -------------------------------------------------------------------------
    // Raw base58btc — spec's base58btc() function (no multibase prefix)
    // Used for: SCID, entry hashes, nextKeyHashes
    // -------------------------------------------------------------------------

    /**
     * Encodes {@code bytes} as raw base58btc (Bitcoin alphabet, no prefix).
     *
     * <p>This is the spec's {@code base58btc()} function per {@code draft-msporny-base58-03}.
     *
     * @param bytes the raw bytes to encode
     * @return the base58btc-encoded string (no prefix)
     */
    public static String base58btcEncode(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        String multibase = Multibase.encode(Multibase.Base.Base58BTC, bytes);
        return multibase.substring(1); // strip the 'z' multibase prefix
    }

    /**
     * Decodes a raw base58btc string (no multibase prefix expected).
     *
     * @param encoded the base58btc-encoded string (must not have a {@code z} prefix)
     * @return the decoded raw bytes
     * @throws IllegalArgumentException if the payload is invalid
     */
    public static byte[] base58btcDecode(String encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.isEmpty()) {
            throw new IllegalArgumentException("base58btc string must be non-empty");
        }
        try {
            return Multibase.decode(DidWebVhConstants.MULTIBASE_BASE58BTC_PREFIX + encoded);
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid base58btc payload", e);
        }
    }

    // -------------------------------------------------------------------------
    // Multibase base58btc — with 'z' prefix
    // Used for: proofValue, multikey public keys (updateKeys)
    // -------------------------------------------------------------------------

    /**
     * Encodes {@code bytes} as a multibase base58btc string ({@code z} prefix).
     *
     * @param bytes the raw bytes to encode
     * @return the multibase-encoded string including the {@code z} prefix
     */
    public static String multibaseEncode(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        return Multibase.encode(Multibase.Base.Base58BTC, bytes);
    }

    /**
     * Decodes a multibase base58btc string (strips the {@code z} prefix).
     *
     * @param multibase the multibase string (must start with {@code z})
     * @return the decoded raw bytes
     * @throws IllegalArgumentException if the prefix is not {@code z} or the payload is invalid
     */
    public static byte[] multibaseDecode(String multibase) {
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

    // -------------------------------------------------------------------------
    // Multihash — SHA-256 envelope
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Combined: SHA-256 → multihash → raw base58btc
    // Used for: SCID, entry hashes, nextKeyHashes
    // -------------------------------------------------------------------------

    /**
     * Computes {@code base58btc(multihash(sha256(input)))} — the canonical hash
     * representation used throughout the spec for SCIDs and entry hashes.
     *
     * <p>The result is a raw base58btc string (no {@code z} prefix), starting with
     * {@code Qm} for SHA-256 multihash.
     *
     * @param input the bytes to hash
     * @return the raw base58btc-encoded multihash string
     */
    public static String sha256Multihash(byte[] input) {
        Objects.requireNonNull(input, "input");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input);
            return base58btcEncode(wrapSha256Multihash(digest));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available in this JVM", e);
        }
    }

    // -------------------------------------------------------------------------
    // Multikey — Ed25519 public key encoding
    // -------------------------------------------------------------------------

    /**
     * Encodes a raw Ed25519 public key as a multikey string:
     * {@code multibase(base58btc, [0xed, 0x01] + rawPublicKey)}.
     *
     * @param rawPublicKey the raw 32-byte Ed25519 public key
     * @return the multikey string (starts with {@code z6Mk})
     * @throws IllegalArgumentException if the key is not 32 bytes
     */
    public static String encodeEd25519Multikey(byte[] rawPublicKey) {
        Objects.requireNonNull(rawPublicKey, "rawPublicKey");
        if (rawPublicKey.length != 32) {
            throw new IllegalArgumentException("Expected 32-byte Ed25519 public key, got " + rawPublicKey.length);
        }
        byte[] multikeyBytes = new byte[ED25519_MULTICODEC_PREFIX.length + rawPublicKey.length];
        System.arraycopy(ED25519_MULTICODEC_PREFIX, 0, multikeyBytes, 0, ED25519_MULTICODEC_PREFIX.length);
        System.arraycopy(rawPublicKey, 0, multikeyBytes, ED25519_MULTICODEC_PREFIX.length, rawPublicKey.length);
        return multibaseEncode(multikeyBytes);
    }

    /**
     * Decodes a multikey string to a raw Ed25519 public key.
     *
     * @param multikey the multikey string (must start with {@code z} and contain Ed25519 multicodec prefix)
     * @return the raw 32-byte Ed25519 public key
     * @throws IllegalArgumentException if the format is invalid
     */
    public static byte[] decodeEd25519Multikey(String multikey) {
        Objects.requireNonNull(multikey, "multikey");
        byte[] decoded = multibaseDecode(multikey);
        if (decoded.length < ED25519_MULTICODEC_PREFIX.length) {
            throw new IllegalArgumentException("Multikey too short");
        }
        if (decoded[0] != ED25519_MULTICODEC_PREFIX[0] || decoded[1] != ED25519_MULTICODEC_PREFIX[1]) {
            throw new IllegalArgumentException(
                    "Expected Ed25519 multicodec prefix [0xed, 0x01], got [0x"
                            + String.format("%02x", decoded[0]) + ", 0x" + String.format("%02x", decoded[1]) + "]");
        }
        byte[] rawKey = new byte[decoded.length - ED25519_MULTICODEC_PREFIX.length];
        System.arraycopy(decoded, ED25519_MULTICODEC_PREFIX.length, rawKey, 0, rawKey.length);
        return rawKey;
    }
}
