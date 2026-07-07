import { ADRS, AdrType } from "./adrs.js";
import { merkleRoot, merkleTrace } from "./merkle.js";
import { VariantTools } from "./sphincs.js";
import { generateWotspPkLeaf, traceWotspPkLeaf } from "./wotsp.js";

export function reconstructRoot(
    skSeed: Uint8Array,
    pkSeed: Uint8Array,
    vt: VariantTools,
    adrsSource: ADRS
) {
    //consts
    const H = vt.H;
    const D = vt.D;

    // Top XMSS tree: layer D-1, tree address 0
    const treeADRS = adrsSource.copy();
    treeADRS.setLayerAddress(D - 1);
    treeADRS.setTreeAddress(0n);

    // XMSS Merkle hash node function
    const hashNode = (
        left: Uint8Array, right: Uint8Array,
        height: number, index: number
    ): Uint8Array => {
        const hADRS = treeADRS.copy();
        hADRS.setTypeAndClear(AdrType.TREE);
        hADRS.setTreeHeight(height);
        hADRS.setTreeIndex(index);
        return vt.HASH_H(pkSeed, hADRS, left, right);
    };

    // Build the XMSS tree root
    return merkleRoot(
        hashNode,
        (i: number): Uint8Array => {
            const leafADRS = treeADRS.copy();
            leafADRS.setTypeAndClear(AdrType.WOTS_HASH);
            leafADRS.setKeyPairAddress(i);
            return generateWotspPkLeaf(skSeed, pkSeed, leafADRS, vt);
        },
        H / D
    );
}


export function getHyperTreeRoot(
    ReadNextHash: () => Uint8Array,
    forsRoot: Uint8Array,
    pkSeed: Uint8Array,
    tree: bigint,
    leafIdx: number,
    vt: VariantTools,
    adrsSource: ADRS
): Uint8Array {
    //consts
    const H = vt.H;
    const D = vt.D;
    const hPrime = H / D; // height per XMSS layer = 8

    //for each layer
    let msg = forsRoot;
    let treeIdx = tree;
    let leafIdxCur = leafIdx;
    for (let layer = 0; layer < D; layer++) {
        //addressing
        const adrs = adrsSource.copy();
        adrs.setLayerAddress(layer);
        adrs.setTreeAddress(treeIdx);
        adrs.setTypeAndClear(AdrType.WOTS_HASH);
        adrs.setKeyPairAddress(leafIdxCur);

        //Recover the leaf of WOTS+ Public Key from the {signature + message}
        const leaf = traceWotspPkLeaf(ReadNextHash, pkSeed, msg, adrs, vt);

        //Use Leaf of the WOTS+ Public Key to climb to the root with the authentication path
        const treeADRS = adrs.copy();
        treeADRS.setTypeAndClear(AdrType.TREE);
        treeADRS.setTreeHeight(0);
        treeADRS.setTreeIndex(leafIdxCur);
        //merkle
        const root = merkleTrace<Uint8Array>(
            //Hash
            (left : Uint8Array, right : Uint8Array, queryIndex : number, rootIndex : number) => {
                //address
                treeADRS.setTreeHeight(queryIndex + 1);
                treeADRS.setTreeIndex(rootIndex >> 1);
                //hash
                //same as return HASH_H(pkSeed, treeADRS, left, right);
                return vt.HASH_T(pkSeed, treeADRS, [left, right]);
            },
            //Next Sibling
            (queryIndex : number) => {
                return ReadNextHash();
            },
            //Merkle Trace params
            leaf,
            leafIdxCur,
            hPrime
        );

        //save root for the next round
        msg = root;

        //switch to the upper tree leaf
        leafIdxCur = Number(treeIdx & BigInt((1 << hPrime) - 1));
        //switch to the upper tree
        treeIdx = treeIdx >> BigInt(hPrime);
    }

    //return left root (that is pkRoot (root of the Hyper Tree))
    return msg;
}

