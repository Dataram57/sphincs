import { ADRS } from "../adrs.js";
import { VariantTools } from "../sphincs.js";
import { createHash } from "node:crypto";

function sha256(...chunks: Uint8Array[]): Uint8Array {
    const h = createHash("sha256");

    for (const c of chunks) {
        h.update(c);
    }

    return new Uint8Array(h.digest());
}

function sha512(...chunks: Uint8Array[]): Uint8Array {
    const h = createHash("sha512");

    for (const c of chunks) {
        h.update(c);
    }

    return new Uint8Array(h.digest());
}

const EMPTY = new Uint8Array(0);

function uint8ArrayToBigInt(arr : Uint8Array) : bigint{
    let v = 0n;
    for (const b of arr)
        v = (v << 8n) | BigInt(b);
    return v;
}

//Adds 2 additional bytes at start to the message
function adjustMessage(msg: Uint8Array, ctx: Uint8Array = EMPTY): Uint8Array {
    if (ctx.length > 255) throw new RangeError('context should be 255 bytes or less');
    const out = new Uint8Array(2 + ctx.length + msg.length);
    out[0] = 0;
    out[1] = ctx.length;
    out.set(ctx, 2);
    out.set(msg, 2 + ctx.length);
    return out;
}


//================================================================
//#region SHA2 variations

// I2OSP: encode a non-negative integer as a big-endian byte string of given length
function i2osp(value: number, length: number): Uint8Array {
    const arr = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
        arr[i] = value & 0xff;
        value = value >>> 8;
    }
    return arr;
}


// MGF1 mask generation function, built on SHA-512 (used for Hmsg when n = 24 or 32)
function mgf1Sha512(seed: Uint8Array, length: number): Uint8Array {
    const out = new Uint8Array(length);
    let outOffset = 0;
    let counter = 0;
    while (outOffset < length) {
        const block = sha512(seed, i2osp(counter, 4));
        const toCopy = Math.min(block.length, length - outOffset);
        out.set(block.subarray(0, toCopy), outOffset);
        outOffset += toCopy;
        counter++;
    }
    return out;
}

//#endregion

export class SHA2_VariantTools implements VariantTools {
    //SPHINCS params
    public N : number; //hash length
    public H : number; //Whole Hyper Tree addressing
    public D : number; //How many Merkle trees/layers are in the hyper tree
    public W : number; //Winternitz
    public K : number; //How many FORS trees
    public A : number; //How many levels 1 FORS tree has.


    constructor(
        //params
        N : number = 32,
        H : number = 64,
        D : number = 8,
        W : number = 16,
        K : number = 22,
        A : number = 14,
    ){
        //params
        this.N = N;
        this.H = H;
        this.D = D;
        this.W = W;
        this.K = K;
        this.A = A;
    }


    HASH_PRF_MSG(skPrf: Uint8Array, opt_rand : Uint8Array, message : Uint8Array) : Uint8Array{
    
        //SLH-DSA Using SHA2 for Security Categories 3 and 5
    
        //...
        return sha512(skPrf, opt_rand, message).subarray(0, this.N);
    }
    
    //PRF
    HASH_PRF(skSeed: Uint8Array, pkSeed : Uint8Array, adrs : ADRS) : Uint8Array{
    
        //SLH-DSA Using SHA2 for Security Categories 3 and 5
    
        // PRFaddr: SHA-256(pkSeed || 0^32 || adrs_c || skSeed)
        return sha256(pkSeed, new Uint8Array(this.N), adrs.bytes(), skSeed);
    }
    
    //F
    HASH_F(pkSeed : Uint8Array, adrs : ADRS, input : Uint8Array) : Uint8Array{
    
        //SLH-DSA Using SHA2 for Security Categories 3 and 5
    
        // F (thash1): SHA-256(pkSeed || 0^32 || adrs_c || input)
        return sha256(pkSeed, new Uint8Array(this.N), adrs.bytes(), input);
    }
    
    //T
    HASH_T(pkSeed : Uint8Array, adrs: ADRS, chunks: Uint8Array[]) : Uint8Array{
    
        //SLH-DSA Using SHA2 for Security Categories 3 and 5
    
        // T_l (thashN): SHA-512(pkSeed || 0^96 || adrs_c || ...chunks)[0..N]
        return sha512(pkSeed, new Uint8Array(3 * this.N), adrs.bytes(), ...chunks).subarray(0, this.N);
    }
    
    //H
    HASH_H(pkSeed : Uint8Array, adrs: ADRS, left: Uint8Array, right: Uint8Array) : Uint8Array{
    
        //SLH-DSA Using SHA2 for Security Categories 3 and 5
        
        // H (thashN with 2 blocks): SHA-512(pkSeed || 0^96 || adrs_c || left || right)[0..N]
        return sha512(pkSeed, new Uint8Array(3 * this.N), adrs.bytes(), left, right).subarray(0, this.N);
    }

    hashMessage(message: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, R: Uint8Array){
        const H = this.H;
        const D = this.D;
        const K = this.K;
        const A = this.A;

        //adjust message
        message = adjustMessage(message);

        //consts
        const hPrime = H / D; // height of a single XMSS tree
        //calculations done bytes (not perfect bits)
        const mdBytes = Math.ceil((K * A) / 8); //Addresses all FORS signing sub trees
        const idxTreeBytes = Math.ceil((H - hPrime) / 8);  // 7 bytes   //all XMSS trees
        const idxLeafBytes = Math.ceil(hPrime / 8);        // 1 byte    //bottom Merkle tree
        //magic m
        const m = mdBytes + idxTreeBytes + idxLeafBytes;   // 47 bytes total

        //================================================================
        // Inner hash: SHA-512(R || PK.seed || PK.root || M)
        const inner = sha512(R, pkSeed, pkRoot, message);

        //SHA2 variations
        //Ref: Page 46

        // MGF1 seed: R || PK.seed || inner
        const mgfSeed = new Uint8Array(R.length + pkSeed.length + inner.length);
        mgfSeed.set(R, 0);
        mgfSeed.set(pkSeed, R.length);
        mgfSeed.set(inner, R.length + pkSeed.length);

        const digest = mgf1Sha512(mgfSeed, m);
        //================================================================

        //read stuff from digest
        const md = digest.subarray(0, mdBytes);
        const idxTreeRaw = digest.subarray(mdBytes, mdBytes + idxTreeBytes);
        const idxLeafRaw = digest.subarray(mdBytes + idxTreeBytes, m);


        // toInt(idx_tree) mod 2^(h - h')
        let idxTree = 0n;
        for (const b of idxTreeRaw) idxTree = (idxTree << 8n) | BigInt(b);
        idxTree &= (1n << BigInt(H - hPrime)) - 1n;

        // toInt(idx_leaf) mod 2^h'
        let idxLeaf = 0;
        for (const b of idxLeafRaw) idxLeaf = (idxLeaf << 8) | b;
        idxLeaf &= (1 << hPrime) - 1;

        return { 
            md: md,     //message digest
            //get ids + limit to bits
            tree: uint8ArrayToBigInt(idxTreeRaw) & ((1n << BigInt(H - hPrime)) - 1n),   //bottom tree index
            leafIdx: Number(uint8ArrayToBigInt(idxLeafRaw) & ((1n << BigInt(hPrime)) - 1n)) //leaf index of the bottom tree
        };
    }
    
}

