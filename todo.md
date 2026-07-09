# Implement indepdendent hash function implementations to replace `node:crypto`

Targets:
```ts
// Path: /src/sha2/common.ts
function sha256(...chunks: Uint8Array[]): Uint8Array
function sha512(...chunks: Uint8Array[]): Uint8Array
/* solved */ function hmacSha256(iv : Uint8Array, ...chunks: Uint8Array[]): Uint8Array
/* solved */ function hmacSha512(iv : Uint8Array, ...chunks: Uint8Array[]): Uint8Array

// Path: /src/shake/common.ts
function shake256(n: number, ...chunks: Uint8Array[]): Uint8Array
```

## Solution for HMAC

```ts
//Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
//FIPS PUB 198-1 - Section: 4
function hmac(
    hash: (...chunks: Uint8Array[]) => Uint8Array,
    blockLength: number,
    hashLength: number,     
    key: Uint8Array,
    ...chunks: Uint8Array[]
): Uint8Array {
    //consts
    //FIPS PUB 198-1 - Section: 2.3
    const IPAD = 0x36;
    const OPAD = 0x5c;

    //correct K key block block
    //step 1
    let k: Uint8Array;
    if(key.length > blockLength){
        //step 2
        const hashed = hash(key);
        k = new Uint8Array(blockLength);
        k.set(hashed, 0);
    }else{
        //step 3
        k = new Uint8Array(blockLength);
        k.set(key, 0);
    }

    //xor
    const ipad_part = new Uint8Array(blockLength);
    const opad_part = new Uint8Array(blockLength);
    for(let i = 0; i < blockLength; i++){
        //step 4
        ipad_part[i] = k[i] ^ IPAD;
        
        //step 7
        opad_part[i] = k[i] ^ OPAD;
    }

    //step 5,6
    const innerDigest = hash(ipad_part, ...chunks);

    //step 8,9
    return hash(opad_part, innerDigest);
}

export function hmacSha256(sharedSecret: Uint8Array, ...chunks: Uint8Array[]): Uint8Array {
    return hmac(sha256, 64, 32, sharedSecret, ...chunks);
}
 
export function hmacSha512(sharedSecret: Uint8Array, ...chunks: Uint8Array[]): Uint8Array {
    return hmac(sha512, 128, 64, sharedSecret, ...chunks);
}
```