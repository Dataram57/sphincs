


export enum AdrType {
    WOTS_HASH  = 0,
    WOTS_PK    = 1,
    TREE       = 2,
    FORS_TREE  = 3,
    FORS_ROOTS = 4,
    WOTS_PRF   = 5,
    FORS_PRF   = 6,
}



export interface ADRS {
    setLayerAddress(layer: number): void;
    setTreeAddress(tree: bigint): void;
    setTypeAndClear(type: AdrType): void;

    setKeyPairAddress(idx: number): void;
    getKeyPairAddress(): number;

    setChainAddress(idx: number): void;
    setHashAddress(idx: number): void;

    setTreeHeight(height: number): void;
    setTreeIndex(index: number): void;
    getTreeIndex(): number;

    bytes(): Uint8Array;

    copy(): ADRS;
}
