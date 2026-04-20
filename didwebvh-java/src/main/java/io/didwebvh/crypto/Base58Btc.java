package io.didwebvh.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * Base58btc encoder/decoder using the Bitcoin alphabet.
 *
 * <p>Base58 is a binary-to-text encoding that uses 58 alphanumeric characters,
 * deliberately omitting {@code 0, O, I, l} to avoid visual ambiguity.
 *
 * <p>Leading zero bytes in the input are preserved as leading {@code '1'} characters
 * in the output (the '1' is the zero-digit in base58).
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-msporny-base58-03">draft-msporny-base58-03</a>
 */
final class Base58Btc {

    private static final char[] ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    private static final int[] DECODE_TABLE = new int[128];

    static {
        Arrays.fill(DECODE_TABLE, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            DECODE_TABLE[ALPHABET[i]] = i;
        }
    }

    private Base58Btc() {}

    /**
     * Encodes a byte array to a base58btc string (Bitcoin alphabet, no prefix).
     *
     * @param input the bytes to encode (must not be null)
     * @return the base58btc-encoded string
     */
    static String encode(byte[] input) {
        Objects.requireNonNull(input, "input");
        if (input.length == 0) {
            return "";
        }

        int leadingZeros = 0;
        while (leadingZeros < input.length && input[leadingZeros] == 0) {
            leadingZeros++;
        }

        // Upper bound on output size: log(256)/log(58) ≈ 1.366, so * 138/100 + 1
        byte[] temp = new byte[input.length * 138 / 100 + 1];
        int outputStart = temp.length;

        for (int inputPos = leadingZeros; inputPos < input.length; inputPos++) {
            int carry = input[inputPos] & 0xFF;
            for (int j = temp.length - 1; j >= outputStart || carry != 0; j--) {
                carry += 256 * (temp[j] & 0xFF);
                temp[j] = (byte) (carry % 58);
                carry /= 58;
                if (j <= outputStart) {
                    outputStart = j;
                }
            }
        }

        char[] result = new char[leadingZeros + (temp.length - outputStart)];
        Arrays.fill(result, 0, leadingZeros, ALPHABET[0]); // '1' for each leading zero byte
        for (int i = leadingZeros; i < result.length; i++) {
            result[i] = ALPHABET[temp[outputStart++]];
        }
        return new String(result);
    }

    /**
     * Decodes a base58btc string to a byte array.
     *
     * @param input the base58btc-encoded string (must not be null or empty)
     * @return the decoded bytes
     * @throws IllegalArgumentException if the string contains invalid characters
     */
    static byte[] decode(String input) {
        Objects.requireNonNull(input, "input");
        if (input.isEmpty()) {
            return new byte[0];
        }

        int leadingOnes = 0;
        while (leadingOnes < input.length() && input.charAt(leadingOnes) == ALPHABET[0]) {
            leadingOnes++;
        }

        // Upper bound on output size: log(58)/log(256) ≈ 0.733
        byte[] temp = new byte[input.length() * 733 / 1000 + 1];
        int outputStart = temp.length;

        for (int inputPos = leadingOnes; inputPos < input.length(); inputPos++) {
            char c = input.charAt(inputPos);
            int digit = (c < 128) ? DECODE_TABLE[c] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException(
                        "Invalid base58btc character: '" + c + "' (0x" + Integer.toHexString(c) + ")");
            }

            int carry = digit;
            for (int j = temp.length - 1; j >= outputStart || carry != 0; j--) {
                carry += 58 * (temp[j] & 0xFF);
                temp[j] = (byte) carry;
                carry >>>= 8;
                if (j <= outputStart) {
                    outputStart = j;
                }
            }
        }

        byte[] result = new byte[leadingOnes + (temp.length - outputStart)];
        Arrays.fill(result, 0, leadingOnes, (byte) 0);
        System.arraycopy(temp, outputStart, result, leadingOnes, temp.length - outputStart);
        return result;
    }
}
