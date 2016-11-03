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

/**
 * Utility methods used by both algorithm variants.
 */
final class SipHashUtils {
    private SipHashUtils() {
        throw new UnsupportedOperationException("Utility class");
    }

    static long[] initialState() {
        return new long[] {
                0x736f6d6570736575L, // "somepseu"
                0x646f72616e646f6dL, // "dorandom"
                0x6c7967656e657261L, // "lygenera"
                0x7465646279746573L  // "tedbytes"
        };
    }

    @SuppressWarnings("fallthrough")
    static long lastBits(final byte[] input) {
        final int left = input.length & 7;
        final int len = input.length - (input.length % 8);
        long b = (long) input.length << 56;

        switch (left) {
            case 7:
                b |= ((long) input[len + 6]) << 48;
            case 6:
                b |= ((long) input[len + 5]) << 40;
            case 5:
                b |= ((long) input[len + 4]) << 32;
            case 4:
                b |= ((long) input[len + 3]) << 24;
            case 3:
                b |= ((long) input[len + 2]) << 16;
            case 2:
                b |= ((long) input[len + 1]) << 8;
            case 1:
                b |= ((long) input[len]);
                break;
            case 0:
                break;
        }
        return b;
    }

    /**
     * Implements a single round of the SipHash algorithm.
     *
     * @param state the internal state of the PRF. Must have exactly 4 elements.
     */
    static void sipround(long[] state) {
        long v0 = state[0], v1 = state[1], v2 = state[2], v3 = state[3];

        v0 += v1;
        v2 += v3;
        v1 = Long.rotateLeft(v1, 13);
        v3 = Long.rotateLeft(v3, 16);
        v1 ^= v0;
        v3 ^= v2;

        v0 = Long.rotateLeft(v0, 32);

        v2 += v1;
        v0 += v3;
        v1 = Long.rotateLeft(v1, 17);
        v3 = Long.rotateLeft(v3, 21);
        v1 ^= v2;
        v3 ^= v0;

        v2 = Long.rotateLeft(v2, 32);

        state[0] = v0;
        state[1] = v1;
        state[2] = v2;
        state[3] = v3;
    }

    static void longToBytes(byte[] p, long v) {
        p[0] = (byte) v;
        p[1] = (byte) (v >>> 8);
        p[2] = (byte) (v >>> 16);
        p[3] = (byte) (v >>> 24);
        p[4] = (byte) (v >>> 32);
        p[5] = (byte) (v >>> 40);
        p[6] = (byte) (v >>> 48);
        p[7] = (byte) (v >>> 56);
    }

    static void longToBytesPlus8(byte[] p, long v) {
        p[8] = (byte) v;
        p[9] = (byte) (v >>> 8);
        p[10] = (byte) (v >>> 16);
        p[11] = (byte) (v >>> 24);
        p[12] = (byte) (v >>> 32);
        p[13] = (byte) (v >>> 40);
        p[14] = (byte) (v >>> 48);
        p[15] = (byte) (v >>> 56);
    }

    static long bytesToLong(byte[] p, int offset) {
        return l(p[offset]) | (l(p[offset + 1]) << 8) | (l(p[offset + 2]) << 16) | (l(p[offset + 3]) << 24)
                | (l(p[offset + 4]) << 32) | (l(p[offset + 5]) << 40) | (l(p[offset + 6]) << 48)
                | (l(p[offset + 7]) << 56);
    }

    private static long l(byte b) {
        return b & 0xffL;
    }
}
