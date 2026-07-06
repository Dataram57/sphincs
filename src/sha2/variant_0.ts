import { ADRS } from "../adrs.js";
import { VariantTools } from "../sphincs.js";
import { adjustMessage, mgf1Sha256, sha256, sha512, uint8ArrayToBigInt } from "./common.js";


export class Sha2_VariantTools_1 implements VariantTools {
    //SPHINCS params
    public N : number; //hash length
    public H : number; //Whole Hyper Tree addressing
    public D : number; //How many Merkle trees/layers are in the hyper tree
    public W : number; //Winternitz
    public K : number; //How many FORS trees
    public A : number; //How many levels 1 FORS tree has.
    
    //MGF params
    M : number;

    constructor(
        //params
        N : number = 32,
        H : number = 0,
        D : number = 0,
        W : number = 0,
        K : number = 0,
        A : number = 0,
        //MGF params
        M : number = 0
    ){
        //params
        this.N = N;
        this.H = H;
        this.D = D;
        this.W = W;
        this.K = K;
        this.A = A;
        this.M = M;
    }

    //section 11.2.1

    //TODO: USE HMAC
    HASH_PRF_MSG(skPrf: Uint8Array, opt_rand : Uint8Array, message : Uint8Array) : Uint8Array{
    
        //SLH-DSA Using SHA2 for Security Categories 3 and 5
    
        //...
        return sha512(skPrf, opt_rand, message).subarray(0, this.N);
    }
    
    //PRF
    HASH_PRF(skSeed: Uint8Array, pkSeed : Uint8Array, adrs : ADRS) : Uint8Array{
        return sha256(pkSeed, new Uint8Array(64 - this.N), adrs.bytes(), skSeed).subarray(0, this.N);
    }
    
    //F
    HASH_F(pkSeed : Uint8Array, adrs : ADRS, input : Uint8Array) : Uint8Array{
        return sha256(pkSeed, new Uint8Array(64 - this.N), adrs.bytes(), input).subarray(0, this.N);
    }
    
    //T
    HASH_T(pkSeed : Uint8Array, adrs: ADRS, chunks: Uint8Array[]) : Uint8Array{
        return sha256(pkSeed, new Uint8Array(64 - this.N), adrs.bytes(), ...chunks).subarray(0, this.N);
    }
    
    //H
    HASH_H(pkSeed : Uint8Array, adrs: ADRS, left: Uint8Array, right: Uint8Array) : Uint8Array{
        return sha256(pkSeed, new Uint8Array(64 - this.N), adrs.bytes(), left, right).subarray(0, this.N);
    }

    HASH_MSG(message: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, R: Uint8Array){
        const H = this.H;
        const D = this.D;
        const K = this.K;
        const A = this.A;
        const m = this.M;

        //adjust message
        message = adjustMessage(message);

        //consts
        const hPrime = H / D; // height of a single XMSS tree
        //calculations done bytes (not perfect bits)
        const mdBytes = Math.ceil((K * A) / 8); //Addresses all FORS signing sub trees
        const idxTreeBytes = Math.ceil((H - hPrime) / 8);  // 7 bytes   //all XMSS trees
        const idxLeafBytes = Math.ceil(hPrime / 8);        // 1 byte    //bottom Merkle tree
        //magic m
        //const m = mdBytes + idxTreeBytes + idxLeafBytes;   // 47 bytes total

        //================================================================
        // Inner hash: SHA-512(R || PK.seed || PK.root || M)
        const inner = sha256(R, pkSeed, pkRoot, message);

        //SHA2 variations
        //Ref: Page 46

        // MGF1 seed: R || PK.seed || inner
        const mgfSeed = new Uint8Array(R.length + pkSeed.length + inner.length);
        mgfSeed.set(R, 0);
        mgfSeed.set(pkSeed, R.length);
        mgfSeed.set(inner, R.length + pkSeed.length);

        const digest = mgf1Sha256(mgfSeed, m);
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
