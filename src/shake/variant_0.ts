import { ADRS } from "../adrs.js";
import { VariantTools } from "../sphincs.js";
import { adjustMessage, uint8ArrayToBigInt } from "../utils.js";
import { shake256 } from "./common.js";


export class Shake_VariantTools implements VariantTools {
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

    //section 11.1

    //TODO: USE HMAC
    HASH_PRF_MSG(skPrf: Uint8Array, opt_rand : Uint8Array, message : Uint8Array) : Uint8Array{
        return shake256(this.N, skPrf, opt_rand, message).subarray(0, this.N);
    }
    
    //PRF
    HASH_PRF(skSeed: Uint8Array, pkSeed : Uint8Array, adrs : ADRS) : Uint8Array{
        return shake256(this.N, pkSeed, adrs.bytes(), skSeed).subarray(0, this.N);
    }
    
    //F
    HASH_F(pkSeed : Uint8Array, adrs : ADRS, input : Uint8Array) : Uint8Array {
        return shake256(this.N, pkSeed, adrs.bytes(), input).subarray(0, this.N);
    }
    
    //T
    HASH_T(pkSeed : Uint8Array, adrs: ADRS, chunks: Uint8Array[]) : Uint8Array{
        return shake256(this.N, pkSeed, adrs.bytes(), ...chunks).subarray(0, this.N);
    }
    
    //H
    HASH_H(pkSeed : Uint8Array, adrs: ADRS, left: Uint8Array, right: Uint8Array) : Uint8Array{
        return shake256(this.N, pkSeed, adrs.bytes(), left, right).subarray(0, this.N);
    }

    HASH_MSG(message: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, R: Uint8Array) {
        const H = this.H;
        const K = this.K;
        const A = this.A;
        const M = this.M;
        const hPrime = this.H / this.D;
        
        //adjust message
        message = adjustMessage(message);

        //digest
        const digest = shake256(M, R, pkSeed, pkRoot, message);

        // sizes in bytes, per spec (rounded up from bit lengths)
        const mdLen = Math.ceil((K * A) / 8);
        const treeLen = Math.ceil((H - hPrime) / 8);
        const leafLen = Math.ceil(hPrime / 8);

        if (mdLen + treeLen + leafLen !== M) {
            throw new Error(
                `HASH_MSG length mismatch: mdLen(${mdLen}) + treeLen(${treeLen}) + leafLen(${leafLen}) != M(${M})`
            );
        }

        const md = digest.slice(0, mdLen);
        const idxTreeRaw = digest.slice(mdLen, mdLen + treeLen);
        const idxLeafRaw = digest.slice(mdLen + treeLen, mdLen + treeLen + leafLen);

        const tree =
            uint8ArrayToBigInt(idxTreeRaw) &
            ((1n << BigInt(H - hPrime)) - 1n);

        const leafIdx = Number(
            uint8ArrayToBigInt(idxLeafRaw) & ((1n << BigInt(hPrime)) - 1n)
        );

        return { md, tree, leafIdx };
    }
    
}
