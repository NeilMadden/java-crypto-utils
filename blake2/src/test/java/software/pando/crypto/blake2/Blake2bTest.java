package software.pando.crypto.blake2;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.testng.annotations.Test;

public class Blake2bTest {

    @Test
    public void shouldMatchTestVector() throws Exception {
        // Given
        final byte[] input = "abc".getBytes(StandardCharsets.US_ASCII);
        final int outputSize = 512 / 8;
        final byte[] expected = hex2bin("BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9\n" +
                "                        4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1\n" +
                "                        7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95\n" +
                "                        18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23");

        // When
        final byte[] hash = Blake2b.hash(input, outputSize);

        // Then
        assertThat(hash).isEqualTo(expected);
    }

    static byte[] hex2bin(String hex) {
        final byte[] bin = new BigInteger(hex.replaceAll("\\s+", ""), 16).toByteArray();
        return bin[0] == 0 ? Arrays.copyOfRange(bin, 1, bin.length) : bin;
    }
}