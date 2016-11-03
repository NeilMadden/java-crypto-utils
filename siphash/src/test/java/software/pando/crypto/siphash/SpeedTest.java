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

import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

public class SpeedTest {
    private static final SecretKey KEY = new SecretKeySpec(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }, "RAW");

    public static void main(String...args) throws Exception {

        SipHash sipHash13 = new SipHash(1, 3, KEY);
        SipHash sipHash24Unrolled = new SipHash24(KEY);
        SipHash sipHash24 = new SipHash(2, 4, KEY);
        SipHash sipHash128 = new SipHash128(2, 4, KEY);

        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        hmacSha256.init(KEY);

        final Random random = new Random();
        final byte[] data = new byte[512];
        random.nextBytes(data);

        List<Hash> hashes = Arrays.asList(
                new SH(sipHash13), new SH(sipHash24), new SH(sipHash24Unrolled), new SH(sipHash128),
                new Hmac(hmacSha256), new GuavaHash(Hashing.murmur3_32()), new GuavaHash(Hashing.murmur3_128()), new
                        GuavaHash(Hashing.sipHash24()), new ZackehhSipHash(KEY));
        Map<Hash, Long> bestTime = new HashMap<>();
        for (Hash hash : hashes) {
            bestTime.put(hash, Long.MAX_VALUE);
        }

        for (int i = 1; i <= 5; ++i) {
            System.out.println("Round " + i);
            Collections.shuffle(hashes);
            for (Hash hash : hashes) {
                long totalRounds = 0;
                int rounds = 100_000;
                long start = System.currentTimeMillis();
                long end;
                byte[] output = null;
                do {
                    for (int j = 0; j < rounds; ++j) {
                        output = hash.hash(data);
                    }
                    totalRounds += rounds;
                    end = System.currentTimeMillis();
                    rounds *= 1.2;
                } while ((end - start) < 2000);

                long nsPerIteration = nsPerIter(end, start, totalRounds);
                System.out.printf("%-50.50s %4dns per iteration (output: %16s)%n", hash, nsPerIteration,
                        DatatypeConverter.printHexBinary(output));
                if (nsPerIteration < bestTime.get(hash)) {
                    bestTime.put(hash, nsPerIteration);
                }
            }
        }

        System.out.println("\nBest times:");
        Collections.sort(hashes, (x, y) -> Long.compare(bestTime.get(x), bestTime.get(y)));
        for (Hash hash : hashes) {
            final double nsPerByte = bestTime.get(hash) / (double) data.length;
            System.out.printf("%-50.50s %4dns per iteration (%.2fns/byte = %.2fMB/s)%n", hash, bestTime.get(hash),
                    nsPerByte, 1e9/(nsPerByte * 1024 * 1024));
        }

    }

    private static long nsPerIter(long end, long start, long rounds) {
        return TimeUnit.MILLISECONDS.toNanos(end-start) / rounds;
    }

    interface Hash {
        byte[] hash(byte[] input);
    }

    private static class SH implements Hash {
        private final SipHash impl;

        SH(final SipHash impl) {
            this.impl = impl;
        }

        @Override
        public byte[] hash(final byte[] input) {
            return impl.mac(input);
        }

        @Override
        public String toString() { return impl.toString(); }
    }

    private static class Hmac implements Hash {
        private final Mac mac;

        Hmac(final Mac mac) {
            this.mac = mac;
        }

        @Override
        public byte[] hash(final byte[] message) {
            return mac.doFinal(message);
        }

        @Override
        public String toString() {
            return "Hmac-SHA-256";
        }
    }

    private static class GuavaHash implements Hash {
        private final HashFunction hashFunction;

        GuavaHash(final HashFunction hashFunction) {
            this.hashFunction = hashFunction;
        }

        @Override
        public byte[] hash(final byte[] message) {
            return hashFunction.hashBytes(message).asBytes();
        }

        @Override
        public String toString() {
            return "Guava-" + hashFunction.toString();
        }
    }

    private static class ZackehhSipHash implements Hash {
        private final com.zackehh.siphash.SipHash hash;

        ZackehhSipHash(final Key key) {
            this.hash = new com.zackehh.siphash.SipHash(key.getEncoded());
        }

        @Override
        public byte[] hash(final byte[] message) {
            byte[] out = new byte[8];
            SipHashUtils.longToBytes(out, hash.hash(message).get());
            return out;
        }

        @Override
        public String toString() {
            return "com.zackehh:siphash:1.0.0";
        }
    }
}
