import { ADRS } from "../adrs.js";
import { VariantTools } from "../sphincs.js";
import { concatBytes } from "../utils.js";
import { hmacSha512, mgf1Sha512, sha256, sha512 } from "./common.js";

//FIPS 205 - Section 11.2.2
export class VariantTools_Sha2_3_5 extends VariantTools {

    //H_MSG
    HASH_MSG(messageAdjusted: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, R: Uint8Array){
        const inner = sha512(R, pkSeed, pkRoot, messageAdjusted);
        const mgfSeed = new Uint8Array(R.length + pkSeed.length + inner.length);
        mgfSeed.set(R, 0);
        mgfSeed.set(pkSeed, R.length);
        mgfSeed.set(inner, R.length + pkSeed.length);
        return mgf1Sha512(mgfSeed, this.M);
    }
    
    //PRF
    HASH_PRF(skSeed: Uint8Array, pkSeed : Uint8Array, adrs : ADRS) : Uint8Array{
        return sha256(pkSeed, new Uint8Array(64 - this.N), adrs.bytes(), skSeed).subarray(0, this.N);
    }
    
    //PRF_MSG
    HASH_PRF_MSG(skPrf: Uint8Array, opt_rand : Uint8Array, message : Uint8Array) : Uint8Array{
        return hmacSha512(skPrf, concatBytes([opt_rand, message])).subarray(0, this.N);
    }
    
    //F
    HASH_F(pkSeed : Uint8Array, adrs : ADRS, input : Uint8Array) : Uint8Array{
        return sha256(pkSeed, new Uint8Array(64 - this.N), adrs.bytes(), input).subarray(0, this.N);
    }

    //H
    HASH_H(pkSeed : Uint8Array, adrs: ADRS, left: Uint8Array, right: Uint8Array) : Uint8Array{
        return sha512(pkSeed, new Uint8Array(128 - this.N), adrs.bytes(), left, right).subarray(0, this.N);
    }
    
    //T
    HASH_T(pkSeed : Uint8Array, adrs: ADRS, chunks: Uint8Array[]) : Uint8Array{
        return sha512(pkSeed, new Uint8Array(128 - this.N), adrs.bytes(), ...chunks).subarray(0, this.N);
    }

}

