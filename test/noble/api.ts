import {
    // SHA-2
    slh_dsa_sha2_128s as other_sha2_128s,
    slh_dsa_sha2_128f as other_sha2_128f,
    slh_dsa_sha2_192s as other_sha2_192s,
    slh_dsa_sha2_192f as other_sha2_192f,
    slh_dsa_sha2_256s as other_sha2_256s,
    slh_dsa_sha2_256f as other_sha2_256f,

    // SHAKE
    slh_dsa_shake_128s as other_shake_128s,
    slh_dsa_shake_128f as other_shake_128f,
    slh_dsa_shake_192s as other_shake_192s,
    slh_dsa_shake_192f as other_shake_192f,
    slh_dsa_shake_256s as other_shake_256s,
    slh_dsa_shake_256f as other_shake_256f,
} from "@noble/post-quantum/slh-dsa.js";

function anonymizeSphincs(sphincs : any){
    return Object.freeze({
        keygen: () => sphincs.keygen(),
        sign: (message: Uint8Array, secretKey: Uint8Array) => sphincs.sign(message, secretKey),
        verify: (message: Uint8Array, publicKey: Uint8Array, signature: Uint8Array) => sphincs.verify(signature, message, publicKey)
    });
}

export const slh_dsa_sha2_128s = anonymizeSphincs(other_sha2_128s);
export const slh_dsa_sha2_128f = anonymizeSphincs(other_sha2_128f);
export const slh_dsa_sha2_192s = anonymizeSphincs(other_sha2_192s);
export const slh_dsa_sha2_192f = anonymizeSphincs(other_sha2_192f);
export const slh_dsa_sha2_256s = anonymizeSphincs(other_sha2_256s);
export const slh_dsa_sha2_256f = anonymizeSphincs(other_sha2_256f);

export const slh_dsa_shake_128s = anonymizeSphincs(other_shake_128s);
export const slh_dsa_shake_128f = anonymizeSphincs(other_shake_128f);
export const slh_dsa_shake_192s = anonymizeSphincs(other_shake_192s);
export const slh_dsa_shake_192f = anonymizeSphincs(other_shake_192f);
export const slh_dsa_shake_256s = anonymizeSphincs(other_shake_256s);
export const slh_dsa_shake_256f = anonymizeSphincs(other_shake_256f);