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

import javax.crypto.SecretKey;

/**
 * Implementation of the SipHash family of fast, cryptographically strong pseudorandom functions (PRFs) designed to
 * be used as a general purpose hash algorithm to avoid hash-flooding DoS attacks. This implementation is competitive
 * in performance to other general-purpose Java hash algorithms such as MurmurHash, whilst having significantly
 * stronger cryptographic properties. In particular, it is much more difficult to predict and manufacture hash
 * collisions with SipHash.
 * <p>
 * SipHash can also be used as a Message Authentication Code (MAC) for short messages, but be aware that the output
 * size (64 bits) is considered too small to be secure on its own in this usage. It is better to use a general-purpose
 * MAC for those cases, such as BLAKE2 or SHA-256, which have significantly larger output tag sizes. SipHash can be used
 * in cases where either the format precludes larger tag sizes (such as IP packet authentication) or where there are
 * other mitigations (e.g., rate limiting if only online attacks are possible).
 * <p>
 * The parameters to the algorithm are as follows:
 * <dl>
 *     <dt>compressionRounds</dt><dd>The number of compression rounds to apply. Must be at least 1.</dd>
 *     <dt>finalizationRounds</dt><dd>The number of finalization rounds to apply. Must be at least 3.</dd>
 *     <dt>tagSize</dt><dd>The size of the output tag in bits. Must be either 64 or 128.</dd>
 * </dl>
 * A SipHash algorithm with <em>c</em> compression rounds and <em>f</em> finalization rounds is known as
 * SipHash-<em>c</em>-<em>f</em>. For instance, SipHash-2-4 has 2 compression rounds and 4 finalization rounds. This
 * is the default, as recommended by the SipHash authors. A more conservative choice is SipHash-4-8. This implementation
 * will not allow you to select parameters less than SipHash-1-3. The default output tag size is 64-bits, but we also
 * implement the 128-bit variant, although this has received less analysis.
 * <p>
 * The algorithm is designed to work well with short inputs, typically less than 1KiB in size. The interface is
 * therefore designed to accept the input directly as a single byte array. It is not recommended to use it with
 * significantly larger inputs, as other hash algorithms will likely be faster.
 *
 * @see <a href="http://131002.net/siphash/">SipHash Website</a>
 */
public class SipHash {
    final int compressionRounds;
    final int finalizationRounds;
    final long[] initialState;

    /**
     * Returns a SipHash implementation for the given algorithm parameters.
     *
     * @param compressionRounds the number of compression rounds. Must be at least 1.
     * @param finalizationRounds the number of finalization rounds. Must be at least 3.
     * @param tagSize the output tag size. Must be 64 or 128 bits.
     * @param key the key to use for the hash. Must be RAW and at least 128 bits.
     * @return the configured SipHash instance.
     * @throws IllegalArgumentException if any of the parameters or the key are invalid.
     */
    public static SipHash getInstance(int compressionRounds, int finalizationRounds, int tagSize, SecretKey key) {
        if (compressionRounds < 1) {
            throw new IllegalArgumentException("Must have at least one compression round");
        }
        if (finalizationRounds < 3) {
            throw new IllegalArgumentException("Must have at least three finalization rounds");
        }
        if (tagSize != 64 && tagSize != 128) {
            throw new IllegalArgumentException("Invalid tag size: must be 64 or 128 bits");
        }
        if (key == null || key.getEncoded() == null || key.getEncoded().length < 16) {
            throw new IllegalArgumentException("Invalid key: must be at least 128 bits");
        }
        if (!"RAW".equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("Key should be RAW format");
        }

        if (tagSize == 128) {
            return new SipHash128(compressionRounds, finalizationRounds, key);
        } else if (compressionRounds == 2 && finalizationRounds ==4) {
            // Optimized special case
            return new SipHash24(key);
        } else {
            return new SipHash(compressionRounds, finalizationRounds, key);
        }
    }

    /**
     * Returns a 64-bit output tag SipHash instance with the given parameters.
     *
     * @param compressionRounds the number of compression rounds. Must be at least 1.
     * @param finalizationRounds the number of finalization rounds. Must be at least 3.
     * @param key the key to use for the hash. Must be RAW and at least 128 bits.
     * @return the configured SipHash instance.
     * @throws IllegalArgumentException if any of the parameters or the key are invalid.
     */
    public static SipHash getInstance(int compressionRounds, int finalizationRounds, SecretKey key) {
        return getInstance(compressionRounds, finalizationRounds, 64, key);
    }

    /**
     * Returns a 64-bit SipHash-2-4 implementation.
     *
     * @param key the key to use for the hash. Must be RAW and at least 128 bits.
     * @return the configured SipHash instance.
     * @throws IllegalArgumentException if the key is invalid.
     */
    public static SipHash getInstance(SecretKey key) {
        return getInstance(2, 4, 64, key);
    }

    /**
     * Initialises the algorithm with the given parameters and key.
     */
    SipHash(final int compressionRounds, final int finalizationRounds, final Key key) {
        this.compressionRounds = compressionRounds;
        this.finalizationRounds = finalizationRounds;

        this.initialState = initialState();
        final long k0 = bytesToLong(key.getEncoded(), 0);
        final long k1 = bytesToLong(key.getEncoded(), 8);

        initialState[3] ^= k1;
        initialState[2] ^= k0;
        initialState[1] ^= k1;
        initialState[0] ^= k0;
    }

    public int getMacTagLength() {
        return 64;
    }

    public byte[] mac(final byte[] input) {
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
        state[2] ^= 0xff;
        for (int i = 0; i < finalizationRounds; ++i) {
            sipround(state);
        }

        b = state[0] ^ state[1] ^ state[2] ^ state[3];

        byte[] out = new byte[8];
        longToBytes(out, b);

        return out;
    }


    @Override
    public String toString() {
        return String.format(Locale.ENGLISH, "SipHash-%d-%d (64-bit)", compressionRounds, finalizationRounds);
    }
}
