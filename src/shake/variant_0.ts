import { ADRS } from "../adrs.js";
import { VariantTools } from "../sphincs.js";
import { shake256 } from "./common.js";

//FIPS 205 - Section 11.1
export class VariantTools_Shake extends VariantTools {

    //H_MSG
    HASH_MSG(messageAdjusted: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, R: Uint8Array) {
        return shake256(this.M, R, pkSeed, pkRoot, messageAdjusted);
    }

    //PRF
    HASH_PRF(skSeed: Uint8Array, pkSeed : Uint8Array, adrs : ADRS) : Uint8Array{
        return shake256(this.N, pkSeed, adrs.bytes(), skSeed).subarray(0, this.N);
    }

    //PRF_MSG
    HASH_PRF_MSG(skPrf: Uint8Array, opt_rand : Uint8Array, message : Uint8Array) : Uint8Array{
        return shake256(this.N, skPrf, opt_rand, message).subarray(0, this.N);
    }
    
    //F
    HASH_F(pkSeed : Uint8Array, adrs : ADRS, input : Uint8Array) : Uint8Array {
        return shake256(this.N, pkSeed, adrs.bytes(), input).subarray(0, this.N);
    }
    
    //H
    HASH_H(pkSeed : Uint8Array, adrs: ADRS, left: Uint8Array, right: Uint8Array) : Uint8Array{
        return shake256(this.N, pkSeed, adrs.bytes(), left, right).subarray(0, this.N);
    }

    //T
    HASH_T(pkSeed : Uint8Array, adrs: ADRS, chunks: Uint8Array[]) : Uint8Array{
        return shake256(this.N, pkSeed, adrs.bytes(), ...chunks).subarray(0, this.N);
    }
    
}
