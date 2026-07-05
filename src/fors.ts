import { ADRS, AdrType } from "./adrs.js";
import { merkleProof, merkleTrace } from "./merkle.js";
import { VariantTools } from "./sphincs.js";
import { base2b } from "./utils.js";

export function getSignatureForsRoot(
    message: Uint8Array,
    signature: Uint8Array,
    pkSeed: Uint8Array,
    pkRoot: Uint8Array,
    //other
    md: Uint8Array,
    tree: bigint,
    leafIdx: number,

    //variant specific
    vt : VariantTools,
    adrsSource : ADRS
) {
    const A = vt.A;
    const K = vt.K;
    const N = vt.N;

    // get start information
    //const { md, tree, leafIdx } = hashMessage(message, pkSeed, pkRoot, extractRandomizer(signature));
    // get indexes for each tree
    const indices = base2b(md, A, K);

    // FORS signature (Section 8.4)
    const forsRoots: Uint8Array[] = [];
    const forsAdrs = adrsSource.copy();
    forsAdrs.setLayerAddress(0);

    // for each FORS merkle tree
    for (let i = 0; i < K; i++) {
        // leaf address: type FORS_TREE, height 0, index = i*2^A + indices[i]
        forsAdrs.setTypeAndClear(AdrType.FORS_TREE);
        forsAdrs.setTreeAddress(tree);
        forsAdrs.setKeyPairAddress(leafIdx);
        forsAdrs.setTreeHeight(0);

        //vars used in markleTrace
        let nodeIdx = indices[i];
        let idxOffset = i << A;
        forsAdrs.setTreeIndex(nodeIdx + idxOffset);

        // get leaf sk (skip randomizer block, skip previous trees' sk+authpath blocks)
        let chunkIdx = 1 + i * (1 + A);
        const sk = signature.subarray(chunkIdx * N, chunkIdx * N + N);

        //save new root
        forsRoots.push(
            //trace it
            merkleTrace<Uint8Array>(
                //Hash
                (left: Uint8Array, right: Uint8Array, queryIndex: number, rootIndex: number) => {
                    //address
                    forsAdrs.setTreeHeight(queryIndex + 1);
                    forsAdrs.setTreeIndex(
                        //next rootIndex (go up)
                        (rootIndex >> 1) +
                        //FORS sub tree offset for next root
                        (idxOffset >> (queryIndex + 1))
                    );

                    //hash
                    return vt.HASH_T(pkSeed, forsAdrs, [left, right]);
                },
                //sibling root
                (queryIndex: number) => {
                    chunkIdx++;
                    return signature.subarray(chunkIdx * N, chunkIdx * N + N);
                },
                //start: compute 1 argument root from the secret
                vt.HASH_F(pkSeed, forsAdrs, sk),
                //authentication path
                nodeIdx,
                //tree height
                A
            )
        );
    }

    // Compress the K tree roots into the single FORS public key
    forsAdrs.setTypeAndClear(AdrType.FORS_ROOTS);
    forsAdrs.setTreeAddress(tree);
    forsAdrs.setKeyPairAddress(leafIdx);
    //return
    return vt.HASH_T(pkSeed, forsAdrs, forsRoots);
}

export function signFors(
    WriteHash: (data: Uint8Array) => void,
    md : Uint8Array, tree : bigint, leafIdx : number,
    skSeed: Uint8Array, pkSeed: Uint8Array,
    vt : VariantTools, adrsSource : ADRS
) : Uint8Array {
    const A = vt.A;
    const K = vt.K;

    // get indexes for each tree
    const indices = base2b(md, A, K);

    //FORS roots
    const forsRoots: Uint8Array[] = [];
    
    //FORS addressing for hashes
    const forsAdrs = adrsSource.copy();
    forsAdrs.setLayerAddress(0);


    //for each FORS merkle tree
    for (let i = 0; i < K; i++) {
        // leaf address: type FORS_TREE, height 0, index = i*2^A + indices[i]
        forsAdrs.setTypeAndClear(AdrType.FORS_TREE);
        forsAdrs.setTreeAddress(tree);
        forsAdrs.setKeyPairAddress(leafIdx);
        forsAdrs.setTreeHeight(0);

        //vars used in markleTrace
        let nodeIdx = indices[i];
        let idxOffset = i << A;
        forsAdrs.setTreeIndex(nodeIdx + idxOffset);

        //target secret generation (section 8.1)
        const skADRS = forsAdrs.copy();
        skADRS.setTypeAndClear(AdrType.FORS_PRF);
        skADRS.setKeyPairAddress(forsAdrs.getKeyPairAddress());
        skADRS.setTreeIndex(nodeIdx + idxOffset);
        const sk = vt.HASH_PRF(skSeed, pkSeed, skADRS)

        //write secret leaf
        WriteHash(sk);

        //compute proof
        const proof = merkleProof<Uint8Array>(
            //Hash
            (left, right, height, rootIndex) => {
                //alter fors address
                forsAdrs.setTreeHeight(height);
                forsAdrs.setTreeIndex(rootIndex + (idxOffset >> height));
                //hash
                return vt.HASH_T(pkSeed, forsAdrs, [left, right]);
            },
            //Next member
            (queryIndex : number) : Uint8Array  => {
                //next secret
                skADRS.setTreeIndex(queryIndex + idxOffset);
                const sk = vt.HASH_PRF(skSeed, pkSeed, skADRS)

                //get leaf
                forsAdrs.setTreeHeight(0);
                forsAdrs.setTreeIndex(queryIndex + idxOffset);
                const skLeaf = vt.HASH_F(pkSeed, forsAdrs, sk);
                return skLeaf;
            },
            //target index
            nodeIdx,
            //Height
            A
        );

        //write authentication path
        for(const root of proof.authPath)
            WriteHash(root);

        //save new root
        forsRoots.push(proof.root);
    }

    // Compress the K tree roots into the single FORS public key
    forsAdrs.setTypeAndClear(AdrType.FORS_ROOTS);
    forsAdrs.setTreeAddress(tree);
    forsAdrs.setKeyPairAddress(leafIdx);
    //return
    return vt.HASH_T(pkSeed, forsAdrs, forsRoots);
}