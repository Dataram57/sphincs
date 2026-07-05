import { SHA2_ADRS } from "./sha2/adrs.js";
import { SHA2_VariantTools } from "./sha2/variant.js";
import { SphincsVariant } from "./sphincs.js";

export function hi(): string {
    return "Hi";
}

const sphincs = new SphincsVariant(
    new SHA2_VariantTools(),
    new SHA2_ADRS()
);

const message = new Uint8Array([3,5]);

const { secretKey, publicKey } = sphincs.keygen();
const signature = sphincs.sign(message, secretKey);
console.log(sphincs.verify(message, publicKey, signature)); 