import { ADRS, AdrType } from "./adrs.js";
import { getSignatureForsRoot, signFors } from "./fors.js";
import { getHyperTreeRoot, reconstructRoot } from "./hypertree.js";
import { merkleProof } from "./merkle.js";
import { adjustMessage, extractRandomizer, randomUint8Array, splitDigest, splitPK, splitSK } from "./utils.js";
import { generateWotspPkLeaf, getWotspParams, signWotsp } from "./wotsp.js";

export interface VariantTools{
    //SPHINCS params
    N : number; //hash length
    H : number; //Whole Hyper Tree addressing
    D : number; //How many Merkle trees/layers are in the hyper tree
    W : number; //Winternitz
    K : number; //How many FORS trees
    A : number; //How many levels 1 FORS tree has.

    //MGF params
    M : number;

    //SPHINCS hashing functions
    HASH_PRF_MSG : (skPrf: Uint8Array, opt_rand : Uint8Array, message : Uint8Array) => Uint8Array;
    HASH_PRF : (skSeed: Uint8Array, pkSeed : Uint8Array, adrs : ADRS) => Uint8Array;
    HASH_F : (pkSeed : Uint8Array, adrs : ADRS, input : Uint8Array) => Uint8Array;
    HASH_T : (pkSeed : Uint8Array, adrs: ADRS, chunks: Uint8Array[]) => Uint8Array;
    HASH_H : (pkSeed : Uint8Array, adrs: ADRS, left: Uint8Array, right: Uint8Array) => Uint8Array;
    HASH_MSG : (message: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, R: Uint8Array) => Uint8Array;
}

export class SphincsVariant{
    
    private vt : VariantTools;
    private adrsSource : ADRS;

    constructor(vt : VariantTools, adrsSource : ADRS){
        this.vt = vt;
        this.adrsSource = adrsSource;
    }

    keygen(){
        const N = this.vt.N;

        //essentials
        const skSeed = randomUint8Array(N);
        const skPrf = randomUint8Array(N);
        const pkSeed = randomUint8Array(N);
        const pkRoot = reconstructRoot(skSeed, pkSeed, this.vt, this.adrsSource);

        //combine
        const secretKey = new Uint8Array(4 * N);
        secretKey.set(skSeed, 0);
        secretKey.set(skPrf, N);
        secretKey.set(pkSeed, 2 * N);
        secretKey.set(pkRoot, 3 * N);
        const publicKey = new Uint8Array(2 * N);
        publicKey.set(pkSeed, 0);
        publicKey.set(pkRoot, N);

        //return
        return {
            secretKey,
            publicKey
        };
    }

    verify(message : Uint8Array, publicKey : Uint8Array, signature : Uint8Array){
        //adjust message
        message = adjustMessage(message);
        
        //split publicKey
        const pk = splitPK(publicKey, this.vt);
        
        //signature reader
        let readerOffset = 0;
        const func_readHash = () => {
            const chunk = signature.subarray(readerOffset, readerOffset + this.vt.N);
            readerOffset += chunk.length;
            return chunk;
        };

        //get randomizer
        const R = func_readHash();

        //digest
        const digest = this.vt.HASH_MSG(message, pk.pkSeed, pk.pkRoot, R);
        const {md, leafIdx, tree} = splitDigest(digest, this.vt);

        //compute FORS root
        const forsRoot = getSignatureForsRoot(func_readHash, pk.pkSeed, md, tree, leafIdx, this.vt, this.adrsSource);
        const hyperTreeRoot = getHyperTreeRoot(func_readHash, forsRoot, pk.pkSeed, tree, leafIdx, this.vt, this.adrsSource); 
        
        //check roots
        if(hyperTreeRoot.length == pk.pkRoot.length){
            let i = hyperTreeRoot.length;
            while(i--)
                if(hyperTreeRoot[i] != pk.pkRoot[i])
                    return false;
            return true;
        }
        return false;
    }

    sign(message : Uint8Array, secretKey : Uint8Array){
        const N = this.vt.N;
        const K = this.vt.K;
        const A = this.vt.A;
        const D = this.vt.D;
        const H = this.vt.H;
        const { LEN } = getWotspParams(this.vt);

        //adjust message
        message = adjustMessage(message);

        //split secretKey
        const sk = splitSK(secretKey, this.vt);
        
        //signature size
        const signature = new Uint8Array(N * (1 + K * (1 + A) + D * (LEN + H / D)));
            
        //writer
        let writerOffset = 0;
        const func_write = (data: Uint8Array) => {
            signature.set(data, writerOffset);
            writerOffset += data.length;
        };

        //randomizer (uses skPrf)
        //TODO: Repair this hash
        //const r : Uint8Array = randomUint8Array(N);
        const r = new Uint8Array(N);
        const R = this.vt.HASH_PRF_MSG(sk.skPrf, r, message);
        func_write(R);

        //consts
        const hPrime = H / D;

        //digest
        const digest = this.vt.HASH_MSG(message, sk.pkSeed, sk.pkRoot, R);
        const {md, leafIdx, tree} = splitDigest(digest, this.vt);

        //fors
        const forsRoot = signFors(func_write, md, tree, leafIdx, sk.skSeed, sk.pkSeed, this.vt, this.adrsSource);

        //HyperTree
        let msg = forsRoot;
        let treeIdx = tree;
        let leafIdxCur = leafIdx;
        for (let layer = 0; layer < D; layer++) {

            //addressing
            const adrs = this.adrsSource.copy();
            adrs.setLayerAddress(layer);
            adrs.setTreeAddress(treeIdx);
            adrs.setTypeAndClear(AdrType.WOTS_HASH);
            adrs.setKeyPairAddress(leafIdxCur);

            //wots signature
            signWotsp(func_write, msg, sk.skSeed, sk.pkSeed, adrs, this.vt);

            //Use Leaf of the WOTS+ Public Key to climb to the root with the authentication path
            const treeADRS = adrs.copy();
            treeADRS.setTypeAndClear(AdrType.TREE);
            treeADRS.setTreeHeight(0);
            treeADRS.setTreeIndex(leafIdxCur);

            //Get merkle proof
            const proof = merkleProof<Uint8Array>(
                //hash
                (left : Uint8Array, right : Uint8Array, height : number, index : number) : Uint8Array => {
                    //address
                    treeADRS.setTreeHeight(height);
                    treeADRS.setTreeIndex(index);
                    //hash
                    //same as return HASH_H(pkSeed, treeADRS, left, right);
                    return this.vt.HASH_T(sk.pkSeed, treeADRS, [left, right]);
                },
                //Next member
                (queryIndex : number) : Uint8Array => {
                    const leafADRS = treeADRS.copy();
                    leafADRS.setTypeAndClear(AdrType.WOTS_HASH);
                    leafADRS.setKeyPairAddress(queryIndex);
                    return generateWotspPkLeaf(sk.skSeed, sk.pkSeed, leafADRS, this.vt);
                },
                //authentication path
                leafIdxCur,
                //height
                hPrime
            );

            //write authentication path
            for(const root of proof.authPath)
                func_write(root);

            //save root for the next round
            msg = proof.root;

            //switch to the upper tree leaf
            leafIdxCur = Number(treeIdx & BigInt((1 << hPrime) - 1));
            //switch to the upper tree
            treeIdx = treeIdx >> BigInt(hPrime);
        }

        //check root
        let i = msg.length;
        while(i--)
            if(msg[i] != sk.pkRoot[i])
                throw new Error(`Signature expected trace to {${sk.pkRoot}}, but got {${msg}}`);

        //return final signature
        return signature;
    }

};
