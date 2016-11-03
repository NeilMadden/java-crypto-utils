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

/**
 * Manually unrolled SipHash-2-4 implementation for optimal speed.
 */
final class SipHash24 extends SipHash {

    SipHash24(final Key key) {
        super(2, 4, key);
    }
    @Override
    public final byte[] mac(final byte[] input) {
        long state[] = Arrays.copyOf(initialState, 4);

        int len = input.length - (input.length % 8);
        for (int offset = 0; offset < len; offset += 8) {
            long m = bytesToLong(input, offset);
            state[3] ^= m;

            sipround(state);
            sipround(state);

            state[0] ^= m;
        }

        long b = lastBits(input);

        state[3] ^= b;
        sipround(state);
        sipround(state);

        state[0] ^= b;
        state[2] ^= 0xff;
        sipround(state);
        sipround(state);
        sipround(state);
        sipround(state);

        b = state[0] ^ state[1] ^ state[2] ^ state[3];

        byte[] out = new byte[8];
        longToBytes(out, b);

        return out;
    }

    @Override
    public String toString() {
        return "SipHash-2-4 (64-bit, unrolled)";
    }

}
