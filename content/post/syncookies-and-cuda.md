---
title: "Syncookies and Cuda"
date: 2019-03-17T20:29:23-04:00
tags: [linux, syncookies, cuda]
---

I was recently tasked with coming up with a project that related to security
vulnerabilities in a class that I'm taking. I decided to evaluate the security
of syncookies in Linux against a brute force attack. The end goal was to devise
a way to brute force the secret held by the Linux kernel for use with syncookies
so that artificial syncookies could be fabricated, thus being able to short
circuit the 3-way handshake and generate various types of denial of service
attacks.

## A background of TCP and the 3-way handshake

TCP is defined in [RFC793](https://tools.ieft.org/html/rfc793) originally
prepared for DARPA by USC back when ARPANET was still a thing. TCP is a 'stream'
based protocol - TCP will abstract away the bookkeeping required to move
multiple variably sized blocks of data across a network.

When a 'client' wishes to open a connection to a 'server' of a service, there is
a specific handshake (defined by RFC793, page 31) which occurs:

```
      TCP A                                                TCP B

  1.  CLOSED                                               LISTEN

  2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

  3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

  4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED

  5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED


          Basic 3-Way Handshake for Connection Synchronization

                                Figure 7.
```

In this example, 'TCP A' represents our 'client' and 'TCP B' represents the
listening server. We can see that step 1 shows this.

First, 'TCP A' reaches out to 'TCP B' with a 'SYN' packet. 'TCP B' then responds
with a 'SYN+ACK' packet. This packet acknowledges the 'SYN' it receives (the
connection is now half-open) as well as notifies 'TCP A' that it wishes open the
other direction of the stream. To this, 'TCP A' responds with a plain 'ACK'
which formally fully-opens the stream. At this point, either side may start
sending data to the other - the stream has been fully opened!

Historically (and by historically, we are talking 80-90's historically), when a
TCP connection is being opened, the server maintains simple state of the
half-opened connection. This state takes up memory space in the kernel. If an
attacker wanted to cause a denial of service on the server, it was possible to
forge a lot of these 'half open' connections, using no resources on the client
while a bundle of resources on the server. This imbalance of resources is the
basis of the SYN flood attack.

To mitigate this attack, operating systems implemented syncookies, a
'magic' sequence number backed by cryptography. With syncookies, the resources
previously required after the initial SYN are no longer required as any saved
state instead only needs to be encoded in the sequence number returned to the
client in the SYN+ACK packet. Syncookies are talked about more by D. J.
Bernstein on [cr.yp.to](http://cr.yp.to/syncookies.html).

## Bypassing the 3-way handshake

Bypassing the 3-way handshake would be a pretty bad thing for the following
reasons:

+ Attackers will now have a 'fire and forgettable' way of opening connections on
  a target server, recreating the resource imbalance from before
+ Attackers don't need to use their real IP when sending this TCP ACK packet
+ Opens up reflection DoS attacks for certain services which preemptively send
  data on a TCP connection creation

To achieve this, I tried to calculate how difficult it would be to predict and
mint syncookies with arbitrary source and destination ip/port combinations for a
single running Linux server instance.

## Linux and Syncookies

When writing this (early 2019) Linux had moved on from the original design of
syncookies. As discussed in the previous
[cr.yp.to](http://cr.yp.to/syncookies.html) link, syncookies used to be
organized as the following:

```clike
struct syncookie {
    // an incrementing timesource which increases once every 64 seconds
    uint8_t tmod32 : 5;
    // an index into a table of valid MSS values
    uint8_t mssEnc : 3;
    // a cryptographic hash of the client IP, client port, server IP, port, and tmod32.
    uint32_t cryptoHash : 24; 
};
```

This results in a cookie which is exactly 32 bits large (4 bytes). Some may
notice a few problems with this approach:

+ t is trivially determinable (its always the first 5 bits!)
+ mss is also trivially determinable, however this isn't exactly a big deal
+ mss is not hashed in the cryptoHash, so it is able to be mutated without
  consequence. This could cause the mss value to be reset to a small value
  resulting in more packets being transited across the Internet

All and all this isn't all that big of a deal - the cryptographic hash still
should have a secret that is hard to guess, however this does open up the
cryptographic hash to offline attack.

Linux on the other hand takes a different approach to syncookies. Instead of the
standard implementation, Linux instead applies the following algorithm:

```clike
static u32 cookie_hash(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
         u32 count, int c)
{
 net_get_random_once(syncookie_secret, sizeof(syncookie_secret));
 return siphash_4u32((__force u32)saddr, (__force u32)daddr,
       (__force u32)sport << 16 | (__force u32)dport,
       count, &syncookie_secret[c]);
}

static __u32 secure_tcp_syn_cookie(__be32 saddr, __be32 daddr, __be16 sport,
       __be16 dport, __u32 sseq, __u32 data)
{
 /*
  * Compute the secure sequence number.
  * The output should be:
  *   HASH(sec1,saddr,sport,daddr,dport,sec1) + sseq + (count * 2^24)
  *      + (HASH(sec2,saddr,sport,daddr,dport,count,sec2) % 2^24).
  * Where sseq is their sequence number and count increases every
  * minute by 1.
  * As an extra hack, we add a small "data" value that encodes the
  * MSS into the second hash value.
  */
 u32 count = tcp_cookie_time();
 return (cookie_hash(saddr, daddr, sport, dport, 0, 0) +
  sseq + (count << COOKIEBITS) +
  ((cookie_hash(saddr, daddr, sport, dport, count, 1) + data)
   & COOKIEMASK));
}
```

For reference, this is from `net/ipv4/syncookies.c`. You can find an online
reference on the [Linux Github
Mirror](https://github.com/torvalds/linux/blob/master/net/ipv4/syncookies.c#L52).

We can immediately see that Linux's implementation of syncookies is
significantly better than the original specification - you are no longer able to
determine t or mss from the syncookie. In addition, all fields in the syncookie
are encrypted / hashed in some way which makes mutating them difficult without
lots of brute force.

Really, Linux stores only 2 pieces of data within the syncookie which can be
later reversed - the lower 8 bits of the source-sequence number as well as the
`data` value, which on further analysis is an index into the `mss` size array.

We really don't care much about these two pieces of data because we pretty much
already know both of these things - the source sequence number is something that
we provide, and for various mediums the MSS is very well known or can be guessed
fairly reliably.

An important thing to note is the `syncookie_secret`. It is a 2-element array of
128 bit keys for SIPHash. This makes our effective key length 256 bits.
This means that we have `2^256` unique keys to try to crack. This is quite a big
key-space, but there are more problems than just this that we will discuss
later.

## SIPHash

With the new syncookie algorithm, Linux uses a newer cryptographic hash.
[SIPHash](https://131002.net/siphash/) is a pseudorandom function (also known as
a keyed hash function) which is cryptographically sane as well as incredibly
quick. You can read more about it on SIPHash's page, but really the important
thing that stood out to me was that this hash was _quick_. One of the first
things I wanted to determine was just how quickly we could roll through this
hash.

## CUDA accelerating SIPHash

I found the simplest C implementation of SIPHash I could find:
[majek/csiphash](https://github.com/majek/csiphash/blob/master/csiphash.c). With
this, I took the spirit of this code and wrote a CUDA C script which would
benchmark how quickly my GTX970 could roll through hashes.

```clike
#include <iostream>
#include <math.h>

#define THREADS 1024
#define BLOCKS 16

// CUDA SIPHash implementation inspired by 
// https://github.com/majek/csiphash/blob/master/csiphash.c
#define ROTATE(x, b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define HALF_ROUND(a,b,c,d,s,t)   \
        a += b; c += d;    \
        b = ROTATE(b, s) ^ a;   \
        d = ROTATE(d, t) ^ c;   \
        a = ROTATE(a, 32);

#define DOUBLE_ROUND(v0,v1,v2,v3)  \
        HALF_ROUND(v0,v1,v2,v3,13,16);  \
        HALF_ROUND(v2,v1,v0,v3,17,21);  \
        HALF_ROUND(v0,v1,v2,v3,13,16);  \
        HALF_ROUND(v2,v1,v0,v3,17,21);

// SRC is ___Always___ 128 bits (16 bytes)
__global__
void siphash24_16(const void *src, const char key[16], uint64_t *r)
{
    for (int q = 0; q < 524288; q++) {
        const uint64_t *_key = (uint64_t *)key;

        uint64_t v0 = _key[0] ^ 0x736f6d6570736575ULL;
        uint64_t v1 = _key[1] ^ 0x646f72616e646f6dULL;
        uint64_t v2 = _key[0] ^ 0x6c7967656e657261ULL;
        uint64_t v3 = _key[1] ^ 0x7465646279746573ULL;

        // b is always 16 << 56;

        v3 ^= ((uint64_t *) src)[0];
        DOUBLE_ROUND(v0, v1, v2, v3);
        v0 ^= ((uint64_t *) src)[0];

        v3 ^= ((uint64_t *) src)[1];
        DOUBLE_ROUND(v0, v1, v2, v3);
        v0 ^= ((uint64_t *) src)[1];
#define B ( ((uint64_t)16) << 56 )
        v3 ^= B;
        DOUBLE_ROUND(v0, v1, v2, v3);
        v0 ^= B; v2 ^= 0xff;
        DOUBLE_ROUND(v0, v1, v2, v3);
        DOUBLE_ROUND(v0, v1, v2, v3);
        //return (v0 ^ v1) ^ (v2 ^ v3);
   
    if (q == threadIdx.x)
        (r[threadIdx.x + blockIdx.x * blockDim.x]) = (v0 ^ v1) ^ (v2 ^ v3);
    }
}

int main(void)
{
    char *src, *key;
    uint64_t *r;

    cudaMallocManaged(&src, 16);
    cudaMallocManaged(&key, 16);
    cudaMallocManaged(&r, THREADS * BLOCKS * sizeof(uint64_t));

    for (int i = 0; i < 16; i++) {
            key[i] = i;
            src[i] = i;
    }

    siphash24_16<<<BLOCKS, THREADS>>>(src, key, r);

    cudaDeviceSynchronize();
   
    for (int i = 0; i < BLOCKS * THREADS; i++) {
        if (r[0] != r[i]) {
            std::cout << "FAILURE! - " << std::hex << r[0] << " " << r[i] << std::endl;
        }
    }

    std::cout << "Ops: " << std::dec << BLOCKS * THREADS << std::endl;
    std::cout << "Result: 0x" << std::hex << *r << std::endl;

    cudaFree(src);
    cudaFree(key);
    cudaFree(r);

    return 0;
}
```

This code isn't an exact duplicate of majek's implementation - I flattened the
variable data size loop down to accept exactly 128 bits of data, being the exact
size of the data which Linux would throw into the hash. This probably didn't
help us much benchmark wise, but might as well do it to get the absolute best
hash time.

I compiled and ran this program using nvprof, Nvidia's CUDA profiling tool. Here
is a run with the above code:

```
$ /opt/cuda/bin/nvprof ./syncooker
==2205== NVPROF is profiling process 2205, command: ./syncooker
Ops: 16384
Result: 0x3f2acc7f57c29bdb
==2205== Profiling application: ./syncooker
==2205== Profiling result:
            Type  Time(%)      Time     Calls       Avg       Min       Max  Name
 GPU activities:  100.00%  97.621ms         1  97.621ms  97.621ms  97.621ms  siphash24_16(void const *, char const *, unsigned long*)
      API calls:   59.54%  145.66ms         3  48.554ms  10.269us  145.62ms  cudaMallocManaged
                   39.90%  97.626ms         1  97.626ms  97.626ms  97.626ms  cudaDeviceSynchronize
                    0.31%  752.40us        96  7.8370us     240ns  391.54us  cuDeviceGetAttribute
                    0.13%  306.54us         1  306.54us  306.54us  306.54us  cuDeviceTotalMem
                    0.05%  119.29us         1  119.29us  119.29us  119.29us  cudaLaunchKernel
                    0.04%  95.004us         3  31.668us  8.2060us  67.841us  cudaFree
                    0.03%  85.384us         1  85.384us  85.384us  85.384us  cuDeviceGetName
                    0.00%  2.6750us         3     891ns     250ns  2.0340us  cuDeviceGetCount
                    0.00%  2.0840us         1  2.0840us  2.0840us  2.0840us  cuDeviceGetPCIBusId
                    0.00%  1.3420us         2     671ns     270ns  1.0720us  cuDeviceGet
                    0.00%     411ns         1     411ns     411ns     411ns  cuDeviceGetUuid

==2205== Unified Memory profiling result:
Device "GeForce GTX 970 (0)"
   Count  Avg Size  Min Size  Max Size  Total Size  Total Time  Name
       1  8.0000KB  8.0000KB  8.0000KB  8.000000KB  2.080000us  Host To Device
      10  32.000KB  4.0000KB  124.00KB  320.0000KB  37.44000us  Device To Host
Total CPU Page faults: 4
```

We can gather a few things from the above results:

+ Our implementation of SIPHash matches [majek's test vector for 16
  bytes](https://github.com/majek/csiphash/blob/master/test.c#L22)
+ We can derive the effective hash rate from the timing information above

## Effective hash rate

From the above results, we can derive our effective hash rate:

```
97.621ms / (16384 * 524288) = 1.1364580132067203e-08ms
                            = 0.011364580132067204ns
                            = 87.99GH/s

```

So almost 90GH/s. Before jumping the gun, remember that we effectively need to
do two of these hashes per syncookie. However we can improve our odds a bit - we
can rule out 255/256 combinations of the first key by only performing one hash
(instead of then needing to perform the second hash) since we know from the code
above that we will be able to check that the upper 8 bits of the syncookie will
be the lower 8 bits of the `count` variable. We assume that we can somehow
derive the current uptime of the server through some other technique. Thus, we
will be able to immediately rule out the key combination for 255/256 of all keys
by doing simply one hash.

Knowing this, we can determine how long it will take on average to guess a
complete syncookie key. First, lets determine just how many hashes we need.
Trivially we would need `2 * 2 ^ 256` or `2 ^ 257` hashes, however as we noted
above we can be more intelligent about this. Our optimized algorithm will almost
halve the hashes we require:

+ Find a first-half key K1 where the resulting hash on the syncookie's upper 8
  bits is equivalent to `count`'s lower 8 bits.
+ Find a second-half key K2 where the resulting hash resolves correctly to the
  correct `data` value (this is the mss index)

With this strategy, lets determine the total number of hashes we need to do
perform in order to find the complete 256 bit key.

```
2 ^ 128 + (1 / 256) * 2 ^ 128 * 2 ^ 128 =
                      2 ^ 128 + 2 ^ 248 =
    = 4.523128485832664e+74 hashes
    = 4.523128485832664e+74e+65 billion hashes
```

SIPHash has been evaluated to be a cryptographically strong PRF, meaning that
the output is indistinguishable from a uniform random function. We know from
this that we cannot realistically predict the input from the output without
using something along the lines of mass pre-computation.

Thus, with a given input, it is equally likely that our key is any value versus
another. From knowing this, we then can say that on average, we will find the
correct key after searching half of the total key space.

We can modify the calculation above to reflect the average amount of hashes we
will need to crack the syncookie key.

```
2 ^ 128 / 2 + (((1 / 256) * 2 ^ 128 / 2) - 1) * 2 ^ 128 + 2 ^ 128 / 2 =
                                    2 ^ 128 + (2 ^ 119 - 1) * 2 ^ 128 =
    = 2.261564242916332e+74 hashes
    = 2.261564242916332e+65 billion hashes
```

This isn't exactly half of full key space we found above, but it is very close.

Using this we can estimate the average time it would take an attacker to guess
the key. Given the amount of hashes as well as our hash rate, its simple math to
figure how long it would take:

```
0.097621 / (16384 * 524288) * 2 ^ 128 + (2 ^ 119 - 1) * 2 ^ 128 
    = 2.5701728062440553e+63 seconds
    = 8.149964504832748e+55 years
```

Whats more is that in order to be leveraged, this attack has to be done in _real
time_ since every time a server restarts its key is regenerated. Its worth
noting that this is for my GTX 970. Due to the sheer scale of this number
and the very low relative value for cost in guessing a syncookie key, this
attack would be a poor choice for even a state actor to undertake for whatever
end goal they would have.

## Problem with sample sizes

From the last section, most would have determined that such an attack is a lost
cause (which it is). However, to make matters worse, I only calculated the time
it would take to search the entire key space for collisions with one syncookie
sample. Unfortunately, this will not give us the true answer.

The problem is that we are only able to observe the output to the syncookie hash
32 bits per computation. Surprisingly, this presents another challenge being
that our output entropy (the syncookie generated) is too low in relation to our
input entropy (the key). What this results in is that for a sample size of 1
(our one syncookie), and knowing that SIPHash is a PRF, we have `2 ^ 256 / 2 ^
32` or `2 ^ 224` keys which given the same inputs will generate the same output
syncookie.

The answer to this problem is to then check candidate keys against more
generated syncookies to further narrow down syncookie key. I don't know about
how to go about the statistics required to figure out how many syncookies are
really required to determine the full hidden syncookie key, but this is just
another problem which throws a wrench in trying to determine the secret key.

## Reflection

This was a bad idea. There is no way without being the NSA with a massive GPU
cluster available that this attack is halfway feasible. Hardware / ASIC
acceleration may be a possibility which brings this attack a bit more in reach
(if you are curious, have a [VHDL
implementation](https://github.com/pemb/siphash) I found) but hardware
acceleration is notoriously expensive. Really, there are so many better ways to
achieve the benefits of cracking Linux's syncookie key than actually going and
cracking the key. Assuming SIPHash stands to scrutiny, Linux's implementation
of syncookies looks incredibly secure.

