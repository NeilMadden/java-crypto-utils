package software.pando.crypto.blake2;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * Implementation of the Blake2b hash algorithm. This variant is optimised for 64-bit architectures.
 */
public final class Blake2b {
    private static final int BLOCK_SIZE = 128; // in bytes = 1024-bit
    private static final int MAX_OUTPUT_SIZE = 64; // bytes
    private static final int MAX_KEY_SIZE = 64; // bytes
    private static final int STATE_SIZE = 8; // in unsigned 64-bit integers (i.e. a long in Java, but unsigned)
    private static final int NUM_ROUNDS = 12;
    private static final int SALT_SIZE = 16; // bytes

    private static final long[] IV = new long[] {
            0x6A09E667F3BCC908L, 0xBB67AE8584CAA73BL,
            0x3C6EF372FE94F82BL, 0xA54FF53A5F1D36F1L,
            0x510E527FADE682D1L, 0x9B05688C2B3E6C1FL,
            0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L
    };

    private static final byte[][] SIGMA = new byte[][] {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
    };

    private final byte[] buffer = new byte[BLOCK_SIZE];
    private int bufferOffset; // Current offset into buffer
    private final long[] state = new long[STATE_SIZE];
    private long sizeLow, sizeHigh;

    private final int outputSize; // Size of output hash
    private final SecretKey key;

    private boolean needsInitialisation = true;
    private byte[] salt;
    private byte[] personalisation;

    private final long[] v = new long[STATE_SIZE * 2];
    private final long[] m = new long[STATE_SIZE * 2];

    public Blake2b(final SecretKey key, final int outputSize) {
        if (outputSize <= 0 || outputSize > MAX_OUTPUT_SIZE) {
            throw new IllegalArgumentException("output size can only be 1..64 bytes");
        }
        if (key != null && (!"RAW".equals(key.getFormat()) || key.getEncoded() == null
                || key.getEncoded().length > MAX_KEY_SIZE)) {
            throw new IllegalArgumentException("invalid key: must be RAW format and no more than 64 bytes");
        }

        this.outputSize = outputSize;
        this.key = key;
    }

    /**
     * Adds some random salt to the hash to increase entropy of derived material when using Blake2 for key derivation.
     * The hash state will be reinitialised at next usage.
     *
     * @param salt the random salt to add to the initial state. Must be exactly 16 bytes.
     * @return this Blake2b instance customised with the given salt.
     */
    public Blake2b salt(final byte[] salt) {
        if (salt.length != SALT_SIZE) {
            throw new IllegalArgumentException("salt must be exactly 16 bytes");
        }
        this.salt = salt;
        needsInitialisation = true;
        return this;
    }

    /**
     * Adds a personalisation value to the hash for domain separation. The hash state will be reinitialised at next
     * usage.
     *
     * @param personalisation the personalisation string. Must be exactly 16 bytes.
     * @return this Blake2b instance customised with the given personalisation string.
     */
    public Blake2b personalization(final byte[] personalisation) {
        if (personalisation.length != SALT_SIZE) {
            throw new IllegalArgumentException("personalisation must be exactly 16 bytes");
        }
        this.personalisation = personalisation;
        needsInitialisation = true;
        return this;
    }

    private void initialize() {
        System.arraycopy(IV, 0, state, 0, STATE_SIZE);
        final int keyLen = key != null ? key.getEncoded().length : 0;
        state[0] ^= 0x01010000L ^ (keyLen << 8) ^ outputSize;

        if (salt != null) {
            final ByteBuffer saltBuffer = ByteBuffer.wrap(salt).order(ByteOrder.LITTLE_ENDIAN);
            state[4] ^= saltBuffer.getLong();
            state[5] ^= saltBuffer.getLong();
        }

        if (personalisation != null) {
            final ByteBuffer personalisationBuffer = ByteBuffer.wrap(personalisation).order(ByteOrder.LITTLE_ENDIAN);
            state[6] ^= personalisationBuffer.getLong();
            state[7] ^= personalisationBuffer.getLong();
        }

        sizeLow = 0L;
        sizeHigh = 0L;
        bufferOffset = 0;

        if (keyLen > 0) {
            System.arraycopy(key.getEncoded(), 0, buffer, 0, keyLen);
            Arrays.fill(buffer, keyLen, buffer.length, (byte) 0);
            bufferOffset = BLOCK_SIZE;
        }

        needsInitialisation = false;
    }

    public Blake2b(final int outputSize) {
        this(null, outputSize);
    }

    public Blake2b update(final byte[] data) {
        if (needsInitialisation) {
            initialize();
        }

        if (data == null || data.length == 0) {
            return this;
        }

        int remaining = data.length;
        int i = 0;

        if (bufferOffset > 0 && bufferOffset < BLOCK_SIZE) {
            // Existing data in buffer: fill up remaining block and process into hash state
            i = Math.min(remaining, BLOCK_SIZE - bufferOffset);
            System.arraycopy(data, 0, buffer, bufferOffset, i);
            bufferOffset += i;
            remaining -= i;
        }

        // If there is a full block in the buffer then process it
        if (bufferOffset == BLOCK_SIZE) {
            incrementSize(BLOCK_SIZE);
            compress(buffer, 0, false);
            bufferOffset = 0;
        }

        // Fast path: process all full input blocks (except last) directly without copying into buffer
        for (; i < remaining - BLOCK_SIZE; i += BLOCK_SIZE) {
            incrementSize(BLOCK_SIZE);
            compress(data, i, false);
        }

        remaining = remaining % BLOCK_SIZE;
        if (remaining == 0) {
            // The last block must always be copied to the buffer even if there was a full block, in case it is the
            // final block in the message, which is processed specially.
            remaining = BLOCK_SIZE;
        }

        // Copy anything left-over into the the buffer (which must be at 0 now)
        assert bufferOffset == 0;
        System.arraycopy(data, data.length - remaining, buffer, 0, remaining);
        bufferOffset = remaining;

        return this;
    }

    private void incrementSize(int amount) {
        sizeLow += amount;
        if (Long.compareUnsigned(sizeLow, amount) < 0) {
            sizeHigh++;
        }
    }

    public byte[] doFinal() {
        final byte[] output = new byte[outputSize];

        incrementSize(bufferOffset);

        // Fill remaining buffer with zeroes
        Arrays.fill(buffer, bufferOffset, buffer.length, (byte) 0);
        compress(buffer, 0, true);

        for (int i = 0; i < outputSize; ++i) {
            output[i] = (byte) ((state[i >> 3] >> (8 * (i & 7))) & 0xFF);
        }

        needsInitialisation = true;
        return output;
    }

    public byte[] doFinal(final byte[] lastDataBlock) {
        update(lastDataBlock);
        return doFinal();
    }

    public static byte[] hash(final byte[] data, final int outputSize) {
        return new Blake2b(outputSize).doFinal(data);
    }

    public static byte[] mac(final SecretKey key, final byte[] data, final int outputSize) {
        return new Blake2b(key, outputSize).doFinal(data);
    }

    private void compress(byte[] source, int offset, boolean isFinal) {
        initialiseRoundState(source, offset);
        if (isFinal) {
            v[14] = ~v[14];
        }

        // NOTE: the split into small methods here is to allow more aggressive inlining by the JIT. Measure before
        // changing.
        applyRounds();

        state[0] ^= v[0] ^ v[8];
        state[1] ^= v[1] ^ v[9];
        state[2] ^= v[2] ^ v[10];
        state[3] ^= v[3] ^ v[11];
        state[4] ^= v[4] ^ v[12];
        state[5] ^= v[5] ^ v[13];
        state[6] ^= v[6] ^ v[14];
        state[7] ^= v[7] ^ v[15];
    }

    private void applyRounds() {
        for (int round = 0; round < NUM_ROUNDS; ++round) {
            applyRound(round);
        }
    }

    private void applyRound(final int round) {
        mix(v, 0, 4,  8, 12, m[SIGMA[round][ 0]], m[SIGMA[round][ 1]]);
        mix(v, 1, 5,  9, 13, m[SIGMA[round][ 2]], m[SIGMA[round][ 3]]);
        mix(v, 2, 6, 10, 14, m[SIGMA[round][ 4]], m[SIGMA[round][ 5]]);
        mix(v, 3, 7, 11, 15, m[SIGMA[round][ 6]], m[SIGMA[round][ 7]]);
        mix(v, 0, 5, 10, 15, m[SIGMA[round][ 8]], m[SIGMA[round][ 9]]);
        mix(v, 1, 6, 11, 12, m[SIGMA[round][10]], m[SIGMA[round][11]]);
        mix(v, 2, 7,  8, 13, m[SIGMA[round][12]], m[SIGMA[round][13]]);
        mix(v, 3, 4,  9, 14, m[SIGMA[round][14]], m[SIGMA[round][15]]);
    }


    private void initialiseRoundState(final byte[] source, final int offset) {
        System.arraycopy(state, 0, v, 0, STATE_SIZE);
        System.arraycopy(IV, 0, v, STATE_SIZE, STATE_SIZE);
        v[12] ^= sizeLow;
        v[13] ^= sizeHigh;

        final ByteBuffer mBuffer = ByteBuffer.wrap(source, offset, m.length * Long.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN);

        for (int i = 0; i < m.length; ++i) {
            m[i] = mBuffer.getLong();
        }
    }

    private static void mix(long[] v, int a, int b, int c, int d, long x, long y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }
}
