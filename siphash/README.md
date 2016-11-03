# SipHash

A fast implementation of the [SipHash](https://131002.net/siphash/) family of secure keyed-hash (PRF) functions.

Provides implementations of SipHash with both 64-bit and 128-bit output tags. Includes a manually unrolled version of
SipHash-2-4.

## Microbenchmarks

There is a rudimentary benchmarking program in the test classes called `SpeedTest`. It attempts to benchmark this 
implementation against some other hashes: Guava's own SipHash-2-4 and Murmur hashes, and another Java SipHash 
implementation that seemed quite fast in testing. The framework hashes a short message (32 bytes) with each 
implementation for 2 seconds. The best result of 5 rounds is taken for each implementation, and the order is 
randomized on each round to try to balance any JIT/GC activity effects.

All measurements taken on a MacBook Pro 2.6GHz Intel Core i7-4960HQ, using Oracle Java 1.8.0_60 with 
`-server -d64 -XX:+UseCompressedOops -XX:+AggressiveOpts`.

Results for 32-byte messages:

```
SipHash-1-3 (64-bit)                                 58ns per iteration (1.81ns/byte = 526.17MB/s)
SipHash-2-4 (64-bit, unrolled)                       62ns per iteration (1.94ns/byte = 492.22MB/s)
SipHash-2-4 (64-bit)                                 80ns per iteration (2.50ns/byte = 381.47MB/s)
com.zackehh:siphash:1.0.0                            86ns per iteration (2.69ns/byte = 354.86MB/s)
SipHash-2-4 (128-bit)                                94ns per iteration (2.94ns/byte = 324.66MB/s)
Guava-Hashing.murmur3_32(0)                         122ns per iteration (3.81ns/byte = 250.14MB/s)
Guava-Hashing.murmur3_128(0)                        143ns per iteration (4.47ns/byte = 213.41MB/s)
Guava-Hashing.sipHash24(506097522914230528, 108481  155ns per iteration (4.84ns/byte = 196.89MB/s)
Hmac-SHA-256                                       1586ns per iteration (49.56ns/byte = 19.24MB/s)
```

Results for 512-byte messages:

```
SipHash-1-3 (64-bit)                                445ns per iteration (0.87ns/byte = 1097.26MB/s)
SipHash-2-4 (64-bit, unrolled)                      508ns per iteration (0.99ns/byte = 961.18MB/s)
Guava-Hashing.murmur3_128(0)                        527ns per iteration (1.03ns/byte = 926.53MB/s)
SipHash-2-4 (128-bit)                               646ns per iteration (1.26ns/byte = 755.85MB/s)
SipHash-2-4 (64-bit)                                692ns per iteration (1.35ns/byte = 705.61MB/s)
Guava-Hashing.sipHash24(506097522914230528, 108481  897ns per iteration (1.75ns/byte = 544.35MB/s)
Guava-Hashing.murmur3_32(0)                         983ns per iteration (1.92ns/byte = 496.73MB/s)
com.zackehh:siphash:1.0.0                          1049ns per iteration (2.05ns/byte = 465.47MB/s)
Hmac-SHA-256                                       4392ns per iteration (8.58ns/byte = 111.18MB/s)
```

Results for 2048-byte (2KiB) messages:

```
SipHash-1-3 (64-bit)                               1699ns per iteration (0.83ns/byte = 1149.57MB/s)
Guava-Hashing.murmur3_128(0)                       1725ns per iteration (0.84ns/byte = 1132.25MB/s)
SipHash-2-4 (64-bit, unrolled)                     1986ns per iteration (0.97ns/byte = 983.45MB/s)
SipHash-2-4 (128-bit)                              2447ns per iteration (1.19ns/byte = 798.17MB/s)
Guava-Hashing.murmur3_32(0)                        2524ns per iteration (1.23ns/byte = 773.82MB/s)
SipHash-2-4 (64-bit)                               2630ns per iteration (1.28ns/byte = 742.63MB/s)
Guava-Hashing.sipHash24(506097522914230528, 108481 3328ns per iteration (1.63ns/byte = 586.88MB/s)
com.zackehh:siphash:1.0.0                          4169ns per iteration (2.04ns/byte = 468.49MB/s)
Hmac-SHA-256                                       13000ns per iteration (6.35ns/byte = 150.24MB/s)
```

As can be seen, the implementation of SipHash here is competitive with even non-cryptographic hashes for small inputs.
Note that the Murmur hash implementations become more competitive as the message size increases.