/*
 * Copyright (c) 2016 Pando Software Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package software.pando.crypto.siphash;

import static software.pando.crypto.siphash.SipHashUtils.*;

import java.security.Key;
import java.util.Arrays;
import java.util.Locale;

/**
 * 128-bit output SipHash variant.
 */
final class SipHash128 extends SipHash {

    SipHash128(final int compressionRounds, final int finalizationRounds, final Key key) {
        super(compressionRounds, finalizationRounds, key);

        initialState[1] ^= 0xee;
    }

    @Override
    public int getMacTagLength() {
        return 128;
    }

    /**
     * Produces a Message Authentication Code (MAC) tag for the given key and input.
     *
     * @param input the input message to produce a MAC tag for.
     * @return the MAC tag. This will always be exactly 16 bytes long.
     * @throws IllegalArgumentException if the key is not at least 128 bits long.
     */
    public final byte[] mac(final byte[] input) {
        long state[] = Arrays.copyOf(initialState, 4);

        int len = input.length - (input.length % 8);
        for (int offset = 0; offset < len; offset += 8) {
            long m = bytesToLong(input, offset);
            state[3] ^= m;

            for (int i = 0; i < compressionRounds; ++i) {
                sipround(state);
            }

            state[0] ^= m;
        }

        long b = lastBits(input);
        state[3] ^= b;

        for (int i = 0; i < compressionRounds; ++i) {
            sipround(state);
        }

        state[0] ^= b;
        state[2] ^= 0xee;

        for (int i = 0; i < finalizationRounds; ++i) {
            sipround(state);
        }

        b = state[0] ^ state[1] ^ state[2] ^ state[3];

        byte[] out = new byte[16];
        longToBytes(out, b);

        state[1] ^= 0xdd;

        for (int i = 0; i < finalizationRounds; ++i) {
            sipround(state);
        }

        b = state[0] ^ state[1] ^ state[2] ^ state[3];
        longToBytesPlus8(out, b);

        return out;
    }

    @Override
    public String toString() {
        return String.format(Locale.ENGLISH, "SipHash-%d-%d (128-bit)", compressionRounds, finalizationRounds);
    }
}
