import { createHash, createHmac } from "node:crypto";

export function sha256(...chunks: Uint8Array[]): Uint8Array {
    const h = createHash("sha256");
    for(const c of chunks)
        h.update(c);
    return new Uint8Array(h.digest());
}

export function sha512(...chunks: Uint8Array[]): Uint8Array {
    const h = createHash("sha512");
    for(const c of chunks)
        h.update(c);
    return new Uint8Array(h.digest());
}

export function hmacSha256(iv : Uint8Array, ...chunks: Uint8Array[]): Uint8Array{
    const h = createHmac("sha256", iv);
    for(const c of chunks)
        h.update(c);
    return new Uint8Array(h.digest());
}

export function hmacSha512(iv : Uint8Array, ...chunks: Uint8Array[]): Uint8Array{
    const h = createHmac("sha512", iv);
    for(const c of chunks)
        h.update(c);
    return new Uint8Array(h.digest());
}


// I2OSP: encode a non-negative integer as a big-endian byte string of given length
export function i2osp(value: number, length: number): Uint8Array {
    const arr = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
        arr[i] = value & 0xff;
        value = value >>> 8;
    }
    return arr;
}


function mgf1(seed: Uint8Array, length: number, func_hash : (a : Uint8Array, b : Uint8Array) => Uint8Array){
    const out = new Uint8Array(length);
    let outOffset = 0;
    let counter = 0;
    while (outOffset < length) {
        const block = func_hash(seed, i2osp(counter, 4));
        const toCopy = Math.min(block.length, length - outOffset);
        out.set(block.subarray(0, toCopy), outOffset);
        outOffset += toCopy;
        counter++;
    }
    return out;
}

export function mgf1Sha512(seed: Uint8Array, length: number): Uint8Array {
    return mgf1(seed, length, sha512);
}

export function mgf1Sha256(seed: Uint8Array, length: number): Uint8Array {
    return mgf1(seed, length, sha256);
}
