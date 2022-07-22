
Pure rust, portable, secure, and efficient implementations of [CRYSTALS-Kyber](https://pq-crystals.org/kyber/index.shtml) and [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/index.shtml).

## Goals
1. Security and safety:
   1. Leverage Rust's memory safety features
   2. Straightforward API for secure integration
   3. Minimize use of unsafe code, and _fully_ document and verify all unsafe code
   4. Extensive testing and verification
      1. Verified against the C reference implementations and extended KATs
2. Portability:
   1. Targeting 32-bit and 64-bit architectures
      1. Support for: ARMv8, ARMv9, RISC-V, and x86_64
   2. Usable on embedded platforms, with or without an operating system `no_std`
      1. no heap allocation
   3. Platform-specific optimizations shall be considered
3. Efficiency:
   1. Performance (latency, throughput) is a primary goal
   2. Minimize memory (RAM) footprint
   3. Minimize executable size (ROM)

## Kyber
Kyber is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber has been identified as a winner of the NIST post-quantum cryptography project to be used in the upcoming NIST quantum-safe publickey cryptography standard.

## Dilithium
Dilithium is a digital signature scheme that is strongly secure under chosen message attacks based on the hardness of lattice problems over module lattices.
The design of Dilithium is based on the "Fiat-Shamir with Aborts" technique of Lyubashevsky which uses rejection sampling to make lattice-based Fiat-Shamir schemes compact and secure.
`Dilithium3` is the recommended parameter set.