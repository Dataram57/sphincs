import { AdrsCompressed } from "./sha2/adrs.js";
import { VariantTools_Sha2_1 } from "./sha2/variant_0.js";
import { VariantTools_Sha2_3_5 } from "./sha2/variant_1.js";
import { AdrsDefault } from "./shake/adrs.js";
import { VariantTools_Shake } from "./shake/variant_0.js";
import { SphincsVariant } from "./sphincs.js";

function anonymizeSphincs(sphincs : SphincsVariant){
    return Object.freeze({
        keygen: () => sphincs.keygen(),
        sign: (message: Uint8Array, secretKey: Uint8Array) => sphincs.sign(message, secretKey),
        verify: (message: Uint8Array, publicKey: Uint8Array, signature: Uint8Array) => sphincs.verify(message, publicKey, signature)
    });
}



const adrsCompressed = new AdrsCompressed();

//N,H,D,W,K,A,M

//TODO: turn these exports into JSON objects and not objects.

//SLH-DSA-SHA2-128s
export const slh_dsa_sha2_128s = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Sha2_1(
        16,63,7,16,14,12,30
    ),
    adrsCompressed
));

//SLH-DSA-SHA2-128f
export const slh_dsa_sha2_128f = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Sha2_1(
        16,66,22,16,33,6,34
    ),
    adrsCompressed
));

//SLH-DSA-SHA2-192s
export const slh_dsa_sha2_192s = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Sha2_3_5(
        24,63,7,16,17,14,39
    ),
    adrsCompressed
));

//SLH-DSA-SHA2-192f
export const slh_dsa_sha2_192f = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Sha2_3_5(
        24,66,22,16,33,8,42
    ),
    adrsCompressed
));

//SLH-DSA-SHA2-256s
export const slh_dsa_sha2_256s = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Sha2_3_5(
        32,64,8,16,22,14,47
    ),
    adrsCompressed
));

//SLH-DSA-SHA2-256f
export const slh_dsa_sha2_256f = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Sha2_3_5(
        32,68,17,16,35,9,49
    ),
    adrsCompressed
));


const adrsDefault = new AdrsDefault();

//SLH-DSA-SHAKE-128s
export const slh_dsa_shake_128s = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Shake(
        16,63,7,16,14,12,30
    ),
    adrsDefault
));

//SLH-DSA-SHAKE-128f
export const slh_dsa_shake_128f = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Shake(
        16,66,22,16,33,6,34
    ),
    adrsDefault
));

//SLH-DSA-SHAKE-192s
export const slh_dsa_shake_192s = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Shake(
        24,63,7,16,17,14,39
    ),
    adrsDefault
));

//SLH-DSA-SHAKE-192f
export const slh_dsa_shake_192f = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Shake(
        24,66,22,16,33,8,42
    ),
    adrsDefault
));

//SLH-DSA-SHAKE-256s
export const slh_dsa_shake_256s = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Shake(
        32,64,8,16,22,14,47
    ),
    adrsDefault
));

//SLH-DSA-SHAKE-256f
export const slh_dsa_shake_256f = anonymizeSphincs(new SphincsVariant(
    new VariantTools_Shake(
        32,68,17,16,35,9,49
    ),
    adrsDefault
));




/*
const message = new Uint8Array([3,5]);

const sphincs = slh_dsa_sha2_128f;

const { secretKey, publicKey } = sphincs.keygen();
const signature = sphincs.sign(message, secretKey);
console.log(sphincs.verify(message, publicKey, signature)); 
*/