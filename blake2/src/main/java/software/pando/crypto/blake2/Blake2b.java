package software.pando.crypto.blake2;

import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * Implementation of the Blake2b hash algorithm. This variant is optimised for 64-bit architectures.
 */
public final class Blake2b {
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


    private final byte[] buffer = new byte[128];
    private int bufferOffset; // Current offset into buffer
    private final long[] state = new long[8];
    private final long[] size = new long[2];

    private final int outputSize; // Size of output hash
    private final SecretKey key;

    private final long[] v = new long[16];
    private final long[] m = new long[16];

    public Blake2b(final SecretKey key, final int outputSize) {
        if (outputSize <= 0 || outputSize > 64) {
            throw new IllegalArgumentException("output size can only be 1..64 bytes");
        }
        if (key != null && (!"RAW".equals(key.getFormat()) || key.getEncoded() == null
                || key.getEncoded().length > 64)) {
            throw new IllegalArgumentException("invalid key: must be RAW format and no more than 64 bytes");
        }

        this.outputSize = outputSize;
        this.key = key;
        initialize();
    }

    private void initialize() {
        System.arraycopy(IV, 0, state, 0, 8);
        final int keyLen = key != null ? key.getEncoded().length : 0;
        state[0] ^= 0x01010000L ^ (keyLen << 8) ^ outputSize;

        size[0] = 0L;
        size[1] = 0L;
        bufferOffset = 0;

        if (keyLen > 0) {
            update(key.getEncoded());
            bufferOffset = 128;
        }
    }

    public Blake2b(final int outputSize) {
        this(null, outputSize);
    }

    public Blake2b update(final byte[] data) {
        int remaining = data.length;
        int i = 0;
        while (remaining > 0) {
            if (bufferOffset == 128) {
                size[0] += 128;
                if (Long.compareUnsigned(size[0], 128) < 0) {
                    // Carry overflow
                    size[1]++;
                }
                compress(false);
                bufferOffset = 0;
            }
            int added = Math.min(remaining, 128 - bufferOffset);
            System.arraycopy(data, i, buffer, bufferOffset, added);
            bufferOffset += added;
            remaining -= added;
            i += added;
        }

        return this;
    }

    public byte[] doFinal() {
        final byte[] output = new byte[outputSize];

        size[0] += bufferOffset;
        if (Long.compareUnsigned(size[0], bufferOffset) < 0) {
            // Carry overflow
            size[1]++;
        }

        Arrays.fill(buffer, bufferOffset, buffer.length, (byte) 0);
        compress(true);

        for (int i = 0; i < outputSize; ++i) {
            output[i] = (byte) ((state[i >> 3] >> (8 * (i & 7))) & 0xFF);
        }

        initialize();
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

    private void compress(boolean isFinal) {
        System.arraycopy(state, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= size[0];
        v[13] ^= size[1];
        if (isFinal) {
            v[14] = ~v[14];
        }

        for (int i = 0; i < 16; ++i) {
            m[i] = bytesToLongLE(buffer, i * 8);
        }

        for (int i = 0; i < 12; ++i) {
            mix(0, 4,  8, 12, m[SIGMA[i][ 0]], m[SIGMA[i][ 1]]);
            mix(1, 5,  9, 13, m[SIGMA[i][ 2]], m[SIGMA[i][ 3]]);
            mix(2, 6, 10, 14, m[SIGMA[i][ 4]], m[SIGMA[i][ 5]]);
            mix(3, 7, 11, 15, m[SIGMA[i][ 6]], m[SIGMA[i][ 7]]);
            mix(0, 5, 10, 15, m[SIGMA[i][ 8]], m[SIGMA[i][ 9]]);
            mix(1, 6, 11, 12, m[SIGMA[i][10]], m[SIGMA[i][11]]);
            mix(2, 7,  8, 13, m[SIGMA[i][12]], m[SIGMA[i][13]]);
            mix(3, 4,  9, 14, m[SIGMA[i][14]], m[SIGMA[i][15]]);
        }

        for (int i = 0; i < 8; ++i) {
            state[i] ^= v[i] ^ v[i + 8];
        }
    }

    private void mix(int a, int b, int c, int d, long x, long y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    /**
     * Constant-time little-endian bytes to long conversion.
     */
    private static long bytesToLongLE(final byte[] value, final int offset) {
        return ((long) value[offset] & 0xFF) ^
                (((long) value[offset + 1] & 0xFF) << 8) ^
                (((long) value[offset + 2] & 0xFF) << 16) ^
                (((long) value[offset + 3] & 0xFF) << 24) ^
                (((long) value[offset + 4] & 0xFF) << 32) ^
                (((long) value[offset + 5] & 0xFF) << 40) ^
                (((long) value[offset + 6] & 0xFF) << 48) ^
                (((long) value[offset + 7] & 0xFF) << 56);
    }
}
