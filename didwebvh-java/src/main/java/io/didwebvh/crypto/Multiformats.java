package io.didwebvh.crypto;

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
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Decodes a base58btc multibase string (strips the {@code z} prefix).
     *
     * @param multibase the multibase string (must start with {@code z})
     * @return the decoded raw bytes
     * @throws io.didwebvh.exception.InvalidDidException if the prefix is not {@code z}
     */
    public static byte[] decodeBase58btc(String multibase) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Wraps {@code hashBytes} in a SHA-256 multihash envelope ({@code 0x12 0x20} prefix).
     *
     * @param hashBytes a raw 32-byte SHA-256 digest
     * @return the multihash-prefixed byte array (34 bytes total)
     */
    public static byte[] wrapSha256Multihash(byte[] hashBytes) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Computes {@code base58btc(multihash(sha256(input)))} — the canonical hash
     * representation used throughout the spec for SCIDs and entry hashes.
     *
     * @param input the bytes to hash
     * @return the encoded multihash string with {@code z} prefix
     */
    public static String sha256Multihash(byte[] input) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
