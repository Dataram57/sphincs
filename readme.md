# Stateless Hash-Based Digital Signature Standard *... SPHINCS+*

A modern TypeScript implementation of the **SLH-DSA (SPHINCS+)** post-quantum digital signature algorithm defined in **NIST FIPS 205**.

SPHINCS+ is a stateless, hash-based digital signature scheme designed to remain secure against attacks from both classical and quantum computers.

## Features

* ✅ Pure TypeScript implementation
* ✅ NIST FIPS 205 compatible
* ✅ Supports all SHA-2 parameter sets
* ✅ Supports all SHAKE parameter sets
* ✅ Simple API for key generation, signing, and verification
* ✅ Works in **Node.js** and modern TypeScript environments

## Installation

Install via npm:

```bash
npm install @dataram57/sphincs
```

Alternatively, download the contents of [`/src`](/src) and use [`/src/index.ts`](/src/index.ts) directly.

## Usage

```typescript
import {
    // SHA-2
    slh_dsa_sha2_128s,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_192s,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_256s,
    slh_dsa_sha2_256f,

    // SHAKE
    slh_dsa_shake_128s,
    slh_dsa_shake_128f,
    slh_dsa_shake_192s,
    slh_dsa_shake_192f,
    slh_dsa_shake_256s,
    slh_dsa_shake_256f,
} from "@dataram57/sphincs";

// Message to sign
const message = new TextEncoder().encode("Hello SPHINCS+!");

// Choose a parameter set
const sphincs = slh_dsa_sha2_256f;

// Generate a key pair
const { secretKey, publicKey } = sphincs.keygen();

// Sign the message
const signature = sphincs.sign(message, secretKey);

// Verify the signature
const valid = sphincs.verify(message, publicKey, signature);

console.log("Signature valid:", valid);
```
## Testing compatibility

### `@noble/post-quantum` from [`npm`](https://www.npmjs.com/package/@noble/post-quantum)

```sh
npm run test_compatibility/@noble/post-quantum
```

### `sphincsplus` from [`sphincs@github`](https://github.com/sphincs/sphincsplus)

Follow instruction from associated [README.MD](./test/sphincsplus/README.MD) first, and run:

```sh
npm run test_compatibility/sphincsplus
```

## Presentation

* My own presentation about how SPHINCS+ works.
  https://docs.google.com/presentation/d/1Ik8m7rv7W9fCXgJgCMuEECm5ped8yL8CCTa6Q3vPadQ/edit?usp=sharing

## Resources

### Main

* NIST FIPS 205 – Stateless Hash-Based Digital Signature Standard
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf

* SPHINCS+ Official Website
  https://sphincs.org/

* SPHINCS+ Reference Implementation
  https://github.com/sphincs/sphincsplus

### Very helpful

* Hash-Based Signatures
  https://www.youtube.com/watch?list=PLA1qgQLL41STcDn6GCAE36RzId-Xq4JU8

* noble-post-quantum
  https://github.com/paulmillr/noble-post-quantum

## License

This is free and unencumbered software released into the public domain.