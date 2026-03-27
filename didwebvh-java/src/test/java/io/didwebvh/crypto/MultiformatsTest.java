package io.didwebvh.crypto;

import io.didwebvh.exception.InvalidDidException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MultiformatsTest {

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

    @Test
    void encodeDecodeBase58btc_roundTrip() {
        byte[] original = {0x00, 0x01, (byte) 0xff, 0x7e};
        String encoded = Multiformats.encodeBase58btc(original);
        assertThat(encoded).startsWith("z");
        assertThat(Multiformats.decodeBase58btc(encoded)).isEqualTo(original);
    }

    @Test
    void decodeBase58btc_rejectsWrongPrefix() {
        assertThatThrownBy(() -> Multiformats.decodeBase58btc("f00"))
                .isInstanceOf(InvalidDidException.class)
                .hasMessageContaining("base58btc");
    }

    @Test
    void decodeBase58btc_rejectsEmpty() {
        assertThatThrownBy(() -> Multiformats.decodeBase58btc(""))
                .isInstanceOf(InvalidDidException.class);
    }

    @Test
    void decodeBase58btc_rejectsNull() {
        assertThatThrownBy(() -> Multiformats.decodeBase58btc(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("multibase");
    }

    /**
     * Independent vectors: SHA-256 digest + multihash prefix, then base58btc with {@code z}
     * (same construction as {@link Multiformats#sha256Multihash}).
     */
    @Test
    void sha256Multihash_knownVectors() throws NoSuchAlgorithmException {
        assertThat(Multiformats.sha256Multihash("hello".getBytes(StandardCharsets.UTF_8)))
                .isEqualTo("zQmRN6wdp1S2A5EtjW9A3M1vKSBuQQGcgvuhoMUoEz4iiT5");

        assertThat(Multiformats.sha256Multihash(new byte[0]))
                .isEqualTo("zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n");
    }
}
