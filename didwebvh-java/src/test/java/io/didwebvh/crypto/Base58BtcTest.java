package io.didwebvh.crypto;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link Base58Btc} using known vectors from
 * <a href="https://datatracker.ietf.org/doc/html/draft-msporny-base58-03#appendix-A">
 * draft-msporny-base58-03 Appendix A</a> and edge cases.
 */
class Base58BtcTest {

    // -------------------------------------------------------------------------
    // Spec vectors from draft-msporny-base58-03 Appendix A
    // -------------------------------------------------------------------------

    @Nested
    class SpecVectors {

        @Test
        void encode_helloWorld() {
            assertThat(Base58Btc.encode("Hello World!".getBytes(StandardCharsets.UTF_8)))
                    .isEqualTo("2NEpo7TZRRrLZSi2U");
        }

        @Test
        void decode_helloWorld() {
            assertThat(Base58Btc.decode("2NEpo7TZRRrLZSi2U"))
                    .isEqualTo("Hello World!".getBytes(StandardCharsets.UTF_8));
        }

        @Test
        void encode_quickBrownFox() {
            assertThat(Base58Btc.encode("The quick brown fox jumps over the lazy dog.".getBytes(StandardCharsets.UTF_8)))
                    .isEqualTo("USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z");
        }

        @Test
        void decode_quickBrownFox() {
            assertThat(Base58Btc.decode("USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"))
                    .isEqualTo("The quick brown fox jumps over the lazy dog.".getBytes(StandardCharsets.UTF_8));
        }

        @Test
        void encode_hexWithLeadingZeroBytes() {
            // 0x0000287fb4cd — 2 leading zero bytes → 2 leading '1's
            assertThat(Base58Btc.encode(hexFromString("0000287fb4cd")))
                    .isEqualTo("11233QC4");
        }

        @Test
        void decode_hexWithLeadingZeroBytes() {
            assertThat(Base58Btc.decode("11233QC4"))
                    .isEqualTo(hexFromString("0000287fb4cd"));
        }
    }

    // -------------------------------------------------------------------------
    // Leading zero bytes
    // -------------------------------------------------------------------------

    @Nested
    class LeadingZeros {

        @Test
        void singleLeadingZero_encodedAs1() {
            byte[] input = {0x00, 0x01};
            String encoded = Base58Btc.encode(input);
            assertThat(encoded).startsWith("1");
            assertThat(Base58Btc.decode(encoded)).isEqualTo(input);
        }

        @Test
        void multipleLeadingZeros_preservedAsOnes() {
            byte[] input = {0x00, 0x00, 0x00, 0x01};
            String encoded = Base58Btc.encode(input);
            assertThat(encoded).startsWith("111");
            assertThat(Base58Btc.decode(encoded)).isEqualTo(input);
        }

        @Test
        void allZeros() {
            byte[] input = {0x00, 0x00, 0x00};
            String encoded = Base58Btc.encode(input);
            assertThat(encoded).isEqualTo("111");
            assertThat(Base58Btc.decode(encoded)).isEqualTo(input);
        }

        @Test
        void hexVector_0000287fb4cd() {
            byte[] input = hexFromString("0000287fb4cd");
            String encoded = Base58Btc.encode(input);
            assertThat(encoded).isEqualTo("11233QC4");
            assertThat(Base58Btc.decode(encoded)).isEqualTo(input);
        }
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    @Nested
    class EdgeCases {

        @Test
        void emptyInput_encodesToEmptyString() {
            assertThat(Base58Btc.encode(new byte[0])).isEmpty();
        }

        @Test
        void emptyString_decodesToEmptyArray() {
            assertThat(Base58Btc.decode("")).isEmpty();
        }

        @Test
        void singleByte_roundTrip() {
            for (int b = 0; b < 256; b++) {
                byte[] input = {(byte) b};
                String encoded = Base58Btc.encode(input);
                assertThat(Base58Btc.decode(encoded)).isEqualTo(input);
            }
        }

        @Test
        void encode_rejectsNull() {
            assertThatThrownBy(() -> Base58Btc.encode(null))
                    .isInstanceOf(NullPointerException.class);
        }

        @Test
        void decode_rejectsNull() {
            assertThatThrownBy(() -> Base58Btc.decode(null))
                    .isInstanceOf(NullPointerException.class);
        }
    }

    // -------------------------------------------------------------------------
    // Invalid input
    // -------------------------------------------------------------------------

    @Nested
    class InvalidCharacters {

        @Test
        void decode_rejectsZero() {
            assertThatThrownBy(() -> Base58Btc.decode("0abc"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'0'");
        }

        @Test
        void decode_rejectsUppercaseO() {
            assertThatThrownBy(() -> Base58Btc.decode("Oabc"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'O'");
        }

        @Test
        void decode_rejectsUppercaseI() {
            assertThatThrownBy(() -> Base58Btc.decode("Iabc"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'I'");
        }

        @Test
        void decode_rejectsLowercaseL() {
            assertThatThrownBy(() -> Base58Btc.decode("labc"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'l'");
        }

        @Test
        void decode_rejectsSpecialChars() {
            assertThatThrownBy(() -> Base58Btc.decode("abc+def"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'+'");
        }
    }

    // -------------------------------------------------------------------------
    // Round-trip with realistic did:webvh-sized payloads
    // -------------------------------------------------------------------------

    @Nested
    class RoundTrips {

        @Test
        void thirtyTwoByteDigest_roundTrip() {
            byte[] sha256 = new byte[32];
            for (int i = 0; i < 32; i++) sha256[i] = (byte) (i * 7 + 3);
            assertThat(Base58Btc.decode(Base58Btc.encode(sha256))).isEqualTo(sha256);
        }

        @Test
        void thirtyFourByteMultihash_roundTrip() {
            byte[] multihash = new byte[34];
            multihash[0] = 0x12;
            multihash[1] = 0x20;
            for (int i = 2; i < 34; i++) multihash[i] = (byte) (i * 13);
            String encoded = Base58Btc.encode(multihash);
            assertThat(encoded).startsWith("Qm");
            assertThat(Base58Btc.decode(encoded)).isEqualTo(multihash);
        }

        @Test
        void sixtyFourByteSignature_roundTrip() {
            byte[] sig = new byte[64];
            for (int i = 0; i < 64; i++) sig[i] = (byte) (i ^ 0xAA);
            assertThat(Base58Btc.decode(Base58Btc.encode(sig))).isEqualTo(sig);
        }
    }

    private static byte[] hexFromString(String hex) {
        int len = hex.length();
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return result;
    }
}
