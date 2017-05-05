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

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Pure Java implementation of the ChaCha20 stream cipher. We implement the <a
 * href="https://tools.ietf.org/html/rfc7539">IETF RFC 7539</a> definition of the cipher mode.
 *
 * @since 1.1.0
 */
public class ChaCha20 {
    public static final String ALGORITHM = "ChaCha20";

    private static final int STATE_LENGTH = 16;
    private static final int KEY_LENGTH = 32;
    private static final int NONCE_LENGTH = 12;
    private static final int BLOCK_COUNTER_OFFSET = 12;
    private static final int BLOCK_LENGTH = STATE_LENGTH * 4;

    private static final long MAX_BLOCKS = Integer.MAX_VALUE * 2L - 1L;

    private final int[] state;

    ChaCha20(final SecretKey key, final byte[] nonce, final int initialCounter) {
        if (!ALGORITHM.equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("Invalid key - not intended for ChaCha20");
        }
        this.state = initialState(key.getEncoded(), nonce, initialCounter);
    }

    public byte[] encrypt(final byte[] plaintext) {
        byte[] ciphertext = new byte[plaintext.length];

        long counter = Integer.toUnsignedLong(state[BLOCK_COUNTER_OFFSET]);
        int numBlocks = (plaintext.length + BLOCK_LENGTH - 1) / BLOCK_LENGTH;
        if (counter + numBlocks >= MAX_BLOCKS) {
            throw new IllegalArgumentException("Message too long - would overflow block counter");
        }

        for (int i = 0; i < numBlocks; ++i) {
            state[BLOCK_COUNTER_OFFSET] = (int)(counter + i);
            byte[] block = blockFunction(state);

            int start = i * BLOCK_LENGTH;
            int end = Math.min(plaintext.length, start + BLOCK_LENGTH);

            for (int j = start; j < end; ++j) {
                ciphertext[j] = (byte) (Byte.toUnsignedInt(block[j - start]) ^ Byte.toUnsignedInt(plaintext[j]));
            }
        }

        return ciphertext;
    }

    /**
     * Performs a ChaCha20 quarter round. See <a href="https://tools.ietf.org/html/rfc7539#section-2.1">RFC 7539 Section
     * 2.1</a>. NB: this implements a fixed permutation on the given indices of the state and is only safe as a building
     * block for the full ChaCha20 block cipher function.
     *
     * @param state the state to perform a quarter-round on.
     * @param a the offset into the state of the first index to permute.
     * @param b the offset into the state of the second index to permute.
     * @param c the offset into the state of the third index to permute.
     * @param d the offset into the state of the fourth index to permute.
     */
    static void quarterRound(int[] state, int a, int b, int c, int d) {
        assert a >= 0 && a < state.length && b >= 0 && b < state.length && c >= 0 && c < state.length && d >= 0 && d < state.length;

        state[a] += state[b]; state[d] = Integer.rotateLeft(state[d] ^ state[a], 16);
        state[c] += state[d]; state[b] = Integer.rotateLeft(state[b] ^ state[c], 12);
        state[a] += state[b]; state[d] = Integer.rotateLeft(state[d] ^ state[a], 8);
        state[c] += state[d]; state[b] = Integer.rotateLeft(state[b] ^ state[c], 7);
    }

    /**
     * Initialises the state based on the given key, nonce and the given initial block counter. See <a
     * href="https://tools.ietf.org/html/rfc7539#section-2.3">RFC 7539 Section 2.3</a> for details.
     *
     * @param key the 256-bit (32-byte) key.
     * @param nonce the 96-bit (12-byte) nonce. This should be unique for each use of the same key. If you are sharing
     *              keys across multiple senders (e.g. servers) then it is recommended that the first 32-bits are a
     *              unique value per-sender, and the remaining bits are a counter that is always incremented.
     * @param initialCount the initial block count.
     * @return the initial state as calculated from the key and nonce.
     */
    static int[] initialState(byte[] key, byte[] nonce, int initialCount) {
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("Key must be exactly 256 bits");
        }
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("Nonce should be 96 bits");
        }

        final int[] state = new int[STATE_LENGTH];

        // Fixed constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key
        ByteBuffer buffer = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 8; ++i) {
            state[4 + i] = buffer.getInt();
        }

        state[12] = initialCount; // Block counter

        // Nonce
        buffer = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN);
        state[13] = buffer.getInt();
        state[14] = buffer.getInt();
        state[15] = buffer.getInt();

        return state;
    }

    /**
     * Performs 20 rounds of the fixed ChaCha20 permutation on the given state.
     *
     * @param workingState the working state to transform.
     */
    static void fixedPermutationRounds(int[] workingState) {
        // Perform the 20 rounds (2 rounds each time through the loop)
        for (int i = 0; i < 10; ++i) {
            // First full round
            quarterRound(workingState, 0, 4, 8,  12);
            quarterRound(workingState, 1, 5, 9,  13);
            quarterRound(workingState, 2, 6, 10, 14);
            quarterRound(workingState, 3, 7, 11, 15);
            // Second full round
            quarterRound(workingState, 0, 5, 10, 15);
            quarterRound(workingState, 1, 6, 11, 12);
            quarterRound(workingState, 2, 7, 8,  13);
            quarterRound(workingState, 3, 4, 9,  14);
        }
    }

    /**
     * Applies the ChaCha20 block function to the given input state. This works in two stages: first, the fixed ChaCha20
     * permutation is applied to the state, then the result is mixed back into the original state using 32-bit modular
     * addition. The second step is vital to convert the fixed (and invertible) permutation into a strong PRF by applying
     * a non-linear transformation to the result.
     *
     * @param state the input state, which must be exactly 16 bytes (128-bits). Will not be changed.
     * @return the serialised updated state in little-endian format.
     */
    static byte[] blockFunction(int[] state) {
        assert state.length == STATE_LENGTH;

        final int[] workingState = Arrays.copyOf(state, STATE_LENGTH);
        fixedPermutationRounds(workingState);

        final ByteBuffer buffer = ByteBuffer.allocate(STATE_LENGTH * 4).order(ByteOrder.LITTLE_ENDIAN);

        // Perform modular addition to mix the result back into the original state to make a PRF out of the fixed permutation.
        for (int i = 0; i < STATE_LENGTH; ++i) {
            buffer.putInt(state[i] + workingState[i]);
        }

        return buffer.array();
    }
}
