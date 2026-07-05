import { VariantTools } from "./sphincs.js";

export function splitSK(
    sk: Uint8Array,
    vt : VariantTools
) {
    const N = vt.N;
    return {
        skSeed: sk.slice(0, N),
        skPrf: sk.slice(N, N + N),
        pkSeed: sk.slice(N + N, N * 3),
        pkRoot: sk.slice(N * 3),
    };
}

export function splitPK(
    pk: Uint8Array,
    vt : VariantTools
) {
    const N = vt.N;
    return {
        pkSeed: pk.slice(0, N),
        pkRoot: pk.slice(N),
    };
}

export function randomUint8Array(length: number): Uint8Array {
    const arr = new Uint8Array(length);
    crypto.getRandomValues(arr);
    return arr;
}

export function extractRandomizer(
    signature : Uint8Array,
    vt : VariantTools
){
    const N = vt.N;
    return signature.subarray(0, N);
}

export function concatBytes(arr: Uint8Array[]): Uint8Array {
    let l = 0;
    for (const bytes of arr) l += bytes.length;
    const x = new Uint8Array(l);
    let offset = 0;
    for (const bytes of arr) {
        x.set(bytes, offset);
        offset += bytes.length;
    }
    return x;
}

// FIPS 205 Algorithm 4 base_2^b: split md into K indices of A bits each.
//used in FORS to get indexes of leafs for K trees
export function base2b(input: Uint8Array, b: number, outLen: number): number[] {
    const mask = (1 << b) - 1;
    const out = new Array<number>(outLen);
    let pos = 0, bits = 0, total = 0;
    for (let i = 0; i < outLen; i++) {
        while (bits < b) {
            total = (total << 8) | input[pos++];
            bits += 8;
        }
        bits -= b;
        out[i] = (total >>> bits) & mask;
    }
    return out;
}

