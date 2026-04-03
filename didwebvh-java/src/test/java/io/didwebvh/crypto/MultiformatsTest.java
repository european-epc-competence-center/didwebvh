package io.didwebvh.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MultiformatsTest {

    // -------------------------------------------------------------------------
    // wrapSha256Multihash
    // -------------------------------------------------------------------------

    @Test
    void wrapSha256Multihash_prefixAndLength() throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes(StandardCharsets.UTF_8));
        byte[] mh = Multiformats.wrapSha256Multihash(digest);

        assertThat(mh).hasSize(34);
        assertThat(mh[0]).isEqualTo((byte) 0x12);
        assertThat(mh[1]).isEqualTo((byte) 0x20);
        assertThat(Arrays.copyOfRange(mh, 2, mh.length)).isEqualTo(digest);
    }

    @Test
    void wrapSha256Multihash_rejectsWrongLength() {
        assertThatThrownBy(() -> Multiformats.wrapSha256Multihash(new byte[31]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32");
        assertThatThrownBy(() -> Multiformats.wrapSha256Multihash(new byte[33]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // -------------------------------------------------------------------------
    // Raw base58btc (no prefix) — used for SCID, entry hashes, nextKeyHashes
    // -------------------------------------------------------------------------

    @Test
    void base58btcEncode_noPrefix() {
        byte[] input = {0x00, 0x01, (byte) 0xff, 0x7e};
        String encoded = Multiformats.base58btcEncode(input);
        assertThat(encoded).doesNotStartWith("z");
    }

    @Test
    void base58btcEncodeDecode_roundTrip() {
        byte[] original = {0x00, 0x01, (byte) 0xff, 0x7e};
        String encoded = Multiformats.base58btcEncode(original);
        assertThat(Multiformats.base58btcDecode(encoded)).isEqualTo(original);
    }

    @Test
    void base58btcDecode_rejectsEmpty() {
        assertThatThrownBy(() -> Multiformats.base58btcDecode(""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void base58btcDecode_rejectsNull() {
        assertThatThrownBy(() -> Multiformats.base58btcDecode(null))
                .isInstanceOf(NullPointerException.class);
    }

    // -------------------------------------------------------------------------
    // Multibase base58btc ('z' prefix) — used for proofValue, multikey
    // -------------------------------------------------------------------------

    @Test
    void multibaseEncodeDecode_roundTrip() {
        byte[] original = {0x00, 0x01, (byte) 0xff, 0x7e};
        String encoded = Multiformats.multibaseEncode(original);
        assertThat(encoded).startsWith("z");
        assertThat(Multiformats.multibaseDecode(encoded)).isEqualTo(original);
    }

    @Test
    void multibaseDecode_rejectsWrongPrefix() {
        assertThatThrownBy(() -> Multiformats.multibaseDecode("f00"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("base58btc");
    }

    @Test
    void multibaseDecode_rejectsEmpty() {
        assertThatThrownBy(() -> Multiformats.multibaseDecode(""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void multibaseDecode_rejectsNull() {
        assertThatThrownBy(() -> Multiformats.multibaseDecode(null))
                .isInstanceOf(NullPointerException.class);
    }

    // -------------------------------------------------------------------------
    // sha256Multihash — raw base58btc (starts with Qm, no 'z' prefix)
    // -------------------------------------------------------------------------

    @Test
    void sha256Multihash_startsWithQm() {
        String hash = Multiformats.sha256Multihash("hello".getBytes(StandardCharsets.UTF_8));
        assertThat(hash).startsWith("Qm");
        assertThat(hash).doesNotStartWith("z");
    }

    /**
     * Known vectors: SHA-256 digest → multihash 0x1220 prefix → raw base58btc.
     * These are the same values as with the 'z' prefix stripped.
     */
    @Test
    void sha256Multihash_knownVectors() throws NoSuchAlgorithmException {
        assertThat(Multiformats.sha256Multihash("hello".getBytes(StandardCharsets.UTF_8)))
                .isEqualTo("QmRN6wdp1S2A5EtjW9A3M1vKSBuQQGcgvuhoMUoEz4iiT5");

        assertThat(Multiformats.sha256Multihash(new byte[0]))
                .isEqualTo("QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n");
    }

    // -------------------------------------------------------------------------
    // Multikey — Ed25519 public key encoding
    // -------------------------------------------------------------------------

    @Test
    void encodeEd25519Multikey_startsWithZ6Mk() {
        byte[] rawKey = new byte[32];
        rawKey[0] = 0x42;
        String multikey = Multiformats.encodeEd25519Multikey(rawKey);
        assertThat(multikey).startsWith("z6Mk");
    }

    @Test
    void encodeDecodeEd25519Multikey_roundTrip() {
        byte[] rawKey = new byte[32];
        for (int i = 0; i < 32; i++) rawKey[i] = (byte) i;
        String multikey = Multiformats.encodeEd25519Multikey(rawKey);
        assertThat(Multiformats.decodeEd25519Multikey(multikey)).isEqualTo(rawKey);
    }

    @Test
    void encodeEd25519Multikey_rejectsWrongKeyLength() {
        assertThatThrownBy(() -> Multiformats.encodeEd25519Multikey(new byte[31]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32");
    }

    @Test
    void decodeEd25519Multikey_rejectsWrongMulticodecPrefix() {
        byte[] wrongPrefix = new byte[34];
        wrongPrefix[0] = 0x01;
        wrongPrefix[1] = 0x02;
        String encoded = Multiformats.multibaseEncode(wrongPrefix);
        assertThatThrownBy(() -> Multiformats.decodeEd25519Multikey(encoded))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Ed25519");
    }

    // -------------------------------------------------------------------------
    // Consistency: raw vs multibase differ only by 'z' prefix
    // -------------------------------------------------------------------------

    @Test
    void rawAndMultibase_differOnlyByPrefix() {
        byte[] data = {(byte) 0x12, (byte) 0x20, 0x01, 0x02, 0x03};
        String raw = Multiformats.base58btcEncode(data);
        String multibase = Multiformats.multibaseEncode(data);
        assertThat(multibase).isEqualTo("z" + raw);
    }
}
