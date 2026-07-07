import { EMPTY } from "./utils.js"



export enum AdrType {
    WOTS_HASH  = 0,
    WOTS_PK    = 1,
    TREE       = 2,
    FORS_TREE  = 3,
    FORS_ROOTS = 4,
    WOTS_PRF   = 5,
    FORS_PRF   = 6,
}



export class ADRS {
    setLayerAddress(layer: number): void{};
    setTreeAddress(tree: bigint): void{};
    setTypeAndClear(type: AdrType): void{};

    setKeyPairAddress(idx: number): void{};
    getKeyPairAddress(): number{return 0};

    setChainAddress(idx: number): void{};
    setHashAddress(idx: number): void{};

    setTreeHeight(height: number): void{};
    setTreeIndex(index: number): void{};
    getTreeIndex(): number{return 0};

    bytes(): Uint8Array{return EMPTY};

    copy(): ADRS{return this};
}
