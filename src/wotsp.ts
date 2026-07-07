import { ADRS, AdrType } from "./adrs.js";
import { VariantTools } from "./sphincs.js";
import { base2b } from "./utils.js";

export function getWotspParams(vt: VariantTools){
    //required
    const N = vt.N;
    const W = vt.W;
    
    //main
    const LOG_W = Math.log2(W);
    const LEN1 = Math.ceil((8 * N) / Math.log2(W));
    const LEN2 = Math.floor(Math.log2(LEN1 * (W - 1)) / Math.log2(W)) + 1;
    const LEN = LEN1 + LEN2;

    return { W, LOG_W, LEN1, LEN2, LEN };
}


export function generateWotspPkLeaf(
    skSeed: Uint8Array,
    pkSeed: Uint8Array,
    adrs: ADRS,
    vt: VariantTools,
): Uint8Array {
    //params
    const { W, LEN } = getWotspParams(vt);

    //consts
    const keypairAddr = adrs.getKeyPairAddress(); // save before any setTypeAndClear
    const wotsp_pk: Uint8Array[] = Array(LEN);

    // PRF adrs: type = WOTS_PRF, keypair preserved, chain iterates
    const skADRS = adrs.copy();
    skADRS.setTypeAndClear(AdrType.WOTS_PRF);
    skADRS.setKeyPairAddress(keypairAddr);

    // Chain adrs: type = WOTS_HASH, keypair preserved, chain + hash iterate
    const chainADRS = adrs.copy();
    chainADRS.setTypeAndClear(AdrType.WOTS_HASH);
    chainADRS.setKeyPairAddress(keypairAddr);

    for (let i = 0; i < LEN; i++) {
        skADRS.setChainAddress(i);
        wotsp_pk[i] = vt.HASH_PRF(skSeed, pkSeed, skADRS);

        chainADRS.setChainAddress(i);
        // Full chain: hash W-1 times (steps 0..W-2)
        for (let f = 0; f < W - 1; f++) {
            chainADRS.setHashAddress(f);
            wotsp_pk[i] = vt.HASH_F(pkSeed, chainADRS, wotsp_pk[i]);
        }
    }

    // Compress WOTS+ pk with T_l
    const pkADRS = adrs.copy();
    pkADRS.setTypeAndClear(AdrType.WOTS_PK);
    pkADRS.setKeyPairAddress(keypairAddr);
    return vt.HASH_T(pkSeed, pkADRS, wotsp_pk);
}


export function chainLengths(msg: Uint8Array, vt: VariantTools): number[] {
    const W = vt.W;
    const { LOG_W, LEN1, LEN2 } = getWotspParams(vt); 

    //convert message to set of LEN1 elements array of size LOG_W bits
    //this satisfies simple WOTS
    const msgDigits = base2b(msg, LOG_W, LEN1);

    //WOTS+ part

    //calculate the checksum
    let checksum = 0;
    for (let i = 0; i < LEN1; i++)
        checksum += (W - 1 - msgDigits[i]);

    // Align checksum to a byte boundary before splitting into base-W digits
    //In other words: Align value to right
    const csumBytesLen = Math.ceil((LEN2 * LOG_W) / 8); // = 2
    const shift = csumBytesLen * 8 - LEN2 * LOG_W;       // = 4
    checksum <<= shift;     //shifr left by number of unused bits

    //split checksum into bytes 
    const csumBytes = new Uint8Array(csumBytesLen);
    for (let i = csumBytesLen - 1; i >= 0; i--) {
        csumBytes[i] = checksum & 0xff;
        checksum >>>= 8;
    }
    //encode as chain lengths
    const csumDigits = base2b(csumBytes, LOG_W, LEN2);

    //return all chain lengths
    return msgDigits.concat(csumDigits);
}

export function traceWotspPkLeaf(
    ReadNextHash: () => Uint8Array,
    pkSeed: Uint8Array,
    msg: Uint8Array,
    adrs: ADRS,
    vt : VariantTools
): Uint8Array {
    const W = vt.W;
    const { LEN } = getWotspParams(vt);
    
    //get chain lengths
    const lengths = chainLengths(msg, vt);

    //address
    const keypairAddr = adrs.getKeyPairAddress();
    const chainADRS = adrs.copy();
    chainADRS.setTypeAndClear(AdrType.WOTS_HASH);
    chainADRS.setKeyPairAddress(keypairAddr);

    //calculate WOTS+ public key from a signature + length
    const pk : Uint8Array[] = new Array(LEN);
    for (let i = 0; i < LEN; i++) {
        //get hash in chain
        let node = ReadNextHash();
        chainADRS.setChainAddress(i);
        //hash it i times
        for (let f = lengths[i]; f < W - 1; f++) {
            chainADRS.setHashAddress(f);
            node = vt.HASH_F(pkSeed, chainADRS, node);
        }
        //assign to the public key
        pk[i] = node;
    }

    //return pk as a leaf of the tree
    const pkADRS = adrs.copy();
    pkADRS.setTypeAndClear(AdrType.WOTS_PK);
    pkADRS.setKeyPairAddress(keypairAddr);
    return vt.HASH_T(pkSeed, pkADRS, pk);
}

export function signWotsp(
    WriteHash: (data: Uint8Array) => void,
    msg: Uint8Array,
    skSeed: Uint8Array,
    pkSeed: Uint8Array,
    adrs: ADRS,
    vt : VariantTools
) {
    //get chain lengths
    const lengths = chainLengths(msg, vt);

    //for each chain length
    let node : Uint8Array;
    for (let i = 0; i < lengths.length; i++) {
        //copy adress
        const skADRS = adrs.copy();
        skADRS.setTypeAndClear(AdrType.WOTS_PRF);
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        skADRS.setChainAddress(i);

        //get secret
        node = vt.HASH_PRF(skSeed, pkSeed, skADRS);

        //addressing for a chain
        const chainADRS = adrs.copy();
        chainADRS.setChainAddress(i);

        //Hash it
        const hashCount = lengths[i]; 
        for(let f = 0; f < hashCount; f++){
            chainADRS.setHashAddress(f);
            node = vt.HASH_F(pkSeed, chainADRS, node);
        }

        //write hash
        WriteHash(node);
    }
}