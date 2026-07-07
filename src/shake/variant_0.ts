import { ADRS } from "../adrs.js";
import { VariantTools } from "../sphincs.js";
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
        N : number,
        H : number,
        D : number,
        W : number,
        K : number,
        A : number,
        //MGF params
        M : number = Math.ceil((K * A) / 8) + Math.ceil((H - H / D) / 8) + Math.ceil(H / D / 8)
    ){
        //params
        this.N = N;
        this.H = H;
        this.D = D;
        this.W = W;
        this.K = K;
        this.A = A;
        //MGF params
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

    HASH_MSG(messageAdjusted: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, R: Uint8Array) {
        return shake256(this.M, R, pkSeed, pkRoot, messageAdjusted);
    }
    
}
