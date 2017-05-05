/*
 * Copyright (c) 2017 Pando Software Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package software.pando.crypto.chacha20;


import org.testng.annotations.Test;

import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class ChaCha20Test {

    @Test
    public void shouldMatchQuarterRoundTestVector() {
        int[] state = { 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567 };

        ChaCha20.quarterRound(state, 0, 1, 2, 3);

        assertThat(state).containsExactly(0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb);
    }

    @Test
    public void shouldMatchQuarterRoundOnChaChaStateTestVector() {
        int[] state = {
                0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
                0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
                0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
                0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
        };

        ChaCha20.quarterRound(state, 2, 7, 8, 13);

        assertThat(state).containsExactly(0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
                                          0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
                                          0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
                                          0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320);
    }

    @Test
    public void shouldMatchKeySetupTestVector() {
        byte[] key = splitOctets("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");
        byte[] nonce = splitOctets("00:00:00:09:00:00:00:4a:00:00:00:00");

        int[] state = ChaCha20.initialState(key, nonce, 1);

        assertThat(state).containsExactly(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                                          0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                                          0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                                          0x00000001, 0x09000000, 0x4a000000, 0x00000000);
    }

    @Test
    public void shouldMatchFixedPermutationTestVector() {
        byte[] key = splitOctets("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");
        byte[] nonce = splitOctets("00:00:00:09:00:00:00:4a:00:00:00:00");
        int[] state = ChaCha20.initialState(key, nonce, 1);

        ChaCha20.fixedPermutationRounds(state);

        assertThat(state).containsExactly(0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
                                          0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
                                          0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
                                          0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2);
    }

    @Test
    public void shouldMatchBlockFunctionTestVector() {
        byte[] key = splitOctets("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");
        byte[] nonce = splitOctets("00:00:00:09:00:00:00:4a:00:00:00:00");
        int[] state = ChaCha20.initialState(key, nonce, 1);

        byte[] block = ChaCha20.blockFunction(state);

        // Verify state was serialised into the keystream correctly
        assertThat(block).containsExactly(
                (byte)0x10, (byte)0xf1, (byte)0xe7, (byte)0xe4, (byte)0xd1, (byte)0x3b, (byte)0x59, (byte)0x15,
                (byte)0x50, (byte)0x0f, (byte)0xdd, (byte)0x1f, (byte)0xa3, (byte)0x20, (byte)0x71, (byte)0xc4,
                (byte)0xc7, (byte)0xd1, (byte)0xf4, (byte)0xc7, (byte)0x33, (byte)0xc0, (byte)0x68, (byte)0x03,
                (byte)0x04, (byte)0x22, (byte)0xaa, (byte)0x9a, (byte)0xc3, (byte)0xd4, (byte)0x6c, (byte)0x4e,
                (byte)0xd2, (byte)0x82, (byte)0x64, (byte)0x46, (byte)0x07, (byte)0x9f, (byte)0xaa, (byte)0x09,
                (byte)0x14, (byte)0xc2, (byte)0xd7, (byte)0x05, (byte)0xd9, (byte)0x8b, (byte)0x02, (byte)0xa2,
                (byte)0xb5, (byte)0x12, (byte)0x9c, (byte)0xd1, (byte)0xde, (byte)0x16, (byte)0x4e, (byte)0xb9,
                (byte)0xcb, (byte)0xd0, (byte)0x83, (byte)0xe8, (byte)0xa2, (byte)0x50, (byte)0x3c, (byte)0x4e);
    }

    @Test
    public void shouldMatchEncryptionTestVector() {
        byte[] key = splitOctets("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");
        byte[] nonce = splitOctets("00:00:00:00:00:00:00:4a:00:00:00:00");
        String message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        final ChaCha20 chacha20 = new ChaCha20(new SecretKeySpec(key, ChaCha20.ALGORITHM), nonce, 1);

        final byte[] cipherText = chacha20.encrypt(message.getBytes(StandardCharsets.UTF_8));

        assertThat(cipherText).containsExactly(
                (byte)0x6e, (byte)0x2e, (byte)0x35, (byte)0x9a, (byte)0x25, (byte)0x68, (byte)0xf9, (byte)0x80,
                (byte)0x41, (byte)0xba, (byte)0x07, (byte)0x28, (byte)0xdd, (byte)0x0d, (byte)0x69, (byte)0x81,
                (byte)0xe9, (byte)0x7e, (byte)0x7a, (byte)0xec, (byte)0x1d, (byte)0x43, (byte)0x60, (byte)0xc2,
                (byte)0x0a, (byte)0x27, (byte)0xaf, (byte)0xcc, (byte)0xfd, (byte)0x9f, (byte)0xae, (byte)0x0b,
                (byte)0xf9, (byte)0x1b, (byte)0x65, (byte)0xc5, (byte)0x52, (byte)0x47, (byte)0x33, (byte)0xab,
                (byte)0x8f, (byte)0x59, (byte)0x3d, (byte)0xab, (byte)0xcd, (byte)0x62, (byte)0xb3, (byte)0x57,
                (byte)0x16, (byte)0x39, (byte)0xd6, (byte)0x24, (byte)0xe6, (byte)0x51, (byte)0x52, (byte)0xab,
                (byte)0x8f, (byte)0x53, (byte)0x0c, (byte)0x35, (byte)0x9f, (byte)0x08, (byte)0x61, (byte)0xd8,
                (byte)0x07, (byte)0xca, (byte)0x0d, (byte)0xbf, (byte)0x50, (byte)0x0d, (byte)0x6a, (byte)0x61,
                (byte)0x56, (byte)0xa3, (byte)0x8e, (byte)0x08, (byte)0x8a, (byte)0x22, (byte)0xb6, (byte)0x5e,
                (byte)0x52, (byte)0xbc, (byte)0x51, (byte)0x4d, (byte)0x16, (byte)0xcc, (byte)0xf8, (byte)0x06,
                (byte)0x81, (byte)0x8c, (byte)0xe9, (byte)0x1a, (byte)0xb7, (byte)0x79, (byte)0x37, (byte)0x36,
                (byte)0x5a, (byte)0xf9, (byte)0x0b, (byte)0xbf, (byte)0x74, (byte)0xa3, (byte)0x5b, (byte)0xe6,
                (byte)0xb4, (byte)0x0b, (byte)0x8e, (byte)0xed, (byte)0xf2, (byte)0x78, (byte)0x5e, (byte)0x42,
                (byte)0x87, (byte) 0x4d
        );
    }

    private static byte[] splitOctets(String octets) {
        String[] parts = octets.split(":");
        byte[] result = new byte[parts.length];

        for (int i = 0; i < parts.length; ++i) {
            result[i] = Byte.parseByte(parts[i], 16);
        }

        return result;
    }
}