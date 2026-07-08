# Implement indepdendent hash function implementations to replace `node:crypto`

Targets:
```ts
// Path: /src/sha2/common.ts
function sha256(...chunks: Uint8Array[]): Uint8Array
function sha512(...chunks: Uint8Array[]): Uint8Array
function hmacSha256(iv : Uint8Array, ...chunks: Uint8Array[]): Uint8Array
function hmacSha512(iv : Uint8Array, ...chunks: Uint8Array[]): Uint8Array

// Path: /src/shake/common.ts
function shake256(n: number, ...chunks: Uint8Array[]): Uint8Array
```