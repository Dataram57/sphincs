import { AdrsCompressed } from "./sha2/adrs.js";
import { Sha2_VariantTools_1 } from "./sha2/variant_0.js";
import { Sha2_VariantTools_3_5 } from "./sha2/variant_1.js";
import { SphincsVariant } from "./sphincs.js";

export function hi(): string {
    return "Hi";
}


const adrsCompressed = new AdrsCompressed();

//N,H,D,W,K,A


//TODO: turn these exports into JSON objects and not objects.

//SLH-DSA-SHA2-128s         (FAILS)
export const slh_dsa_sha2_128s = new SphincsVariant(
    new Sha2_VariantTools_1(
        16,63,7,16,14,12
    ),
    adrsCompressed
);

//SLH-DSA-SHA2-128f         (COMPATIBLE WITH NOBLE)
export const slh_dsa_sha2_128f = new SphincsVariant(
    new Sha2_VariantTools_1(
        16,66,22,16,33,6
    ),
    adrsCompressed
);

//SLH-DSA-SHA2-192s         (FAILS)
export const slh_dsa_sha2_192s = new SphincsVariant(
    new Sha2_VariantTools_3_5(
        24,63,7,16,17,14
    ),
    adrsCompressed
);

//SLH-DSA-SHA2-192f         (FAILS)
export const slh_dsa_sha2_192f = new SphincsVariant(
    new Sha2_VariantTools_3_5(
        24,66,22,16,33,8
    ),
    adrsCompressed
);

//SLH-DSA-SHA2-256s         (COMPATIBLE WITH NOBLE)
export const slh_dsa_sha2_256s = new SphincsVariant(
    new Sha2_VariantTools_3_5(
        32,64,8,16,22,14
    ),
    adrsCompressed
);

//SLH-DSA-SHA2-256f         (COMPATIBLE WITH NOBLE)
export const slh_dsa_sha2_256f = new SphincsVariant(
    new Sha2_VariantTools_3_5(
        32,68,17,16,35,9
    ),
    adrsCompressed
);



// slh_dsa_shake_128f
// slh_dsa_shake_128s
// slh_dsa_shake_192f
// slh_dsa_shake_192s
// slh_dsa_shake_256f
// slh_dsa_shake_256s




const sphincs = new SphincsVariant(
    new Sha2_VariantTools_3_5(),
    adrsCompressed
);




const message = new Uint8Array([3,5]);


const { secretKey, publicKey } = slh_dsa_sha2_256s.keygen();
console.log(secretKey);
console.log(publicKey);

//const signature = sphincs.sign(message, secretKey);
//console.log(sphincs.verify(message, publicKey, signature)); 