import { createHash } from "node:crypto";

export function sha256(...chunks: Uint8Array[]): Uint8Array {
    const h = createHash("sha256");

    for (const c of chunks) {
        h.update(c);
    }

    return new Uint8Array(h.digest());
}

export function sha512(...chunks: Uint8Array[]): Uint8Array {
    const h = createHash("sha512");

    for (const c of chunks) {
        h.update(c);
    }

    return new Uint8Array(h.digest());
}

const EMPTY = new Uint8Array(0);

export function uint8ArrayToBigInt(arr : Uint8Array) : bigint{
    let v = 0n;
    for (const b of arr)
        v = (v << 8n) | BigInt(b);
    return v;
}

//Adds 2 additional bytes at start to the message
export function adjustMessage(msg: Uint8Array, ctx: Uint8Array = EMPTY): Uint8Array {
    if (ctx.length > 255) throw new RangeError('context should be 255 bytes or less');
    const out = new Uint8Array(2 + ctx.length + msg.length);
    out[0] = 0;
    out[1] = ctx.length;
    out.set(ctx, 2);
    out.set(msg, 2 + ctx.length);
    return out;
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
