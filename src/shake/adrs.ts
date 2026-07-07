import { ADRS, AdrType } from "../adrs.js";

export class AdrsDefault implements ADRS {
    buf = new Uint8Array(32);
    private view = new DataView(this.buf.buffer);

    setLayerAddress(layer: number) {
        // full 4-byte field; layer values are tiny so this just zero-pads the top bytes
        this.view.setUint32(0, layer >>> 0, false);
    }

    setTreeAddress(tree: bigint) {
        // 12-byte (96-bit) field: bytes 4-7 high 32 bits (always 0 for realistic tree values),
        // bytes 8-15 low 64 bits, both BE
        this.view.setUint32(4, 0, false);
        this.view.setBigUint64(8, tree, false);
    }

    setTypeAndClear(type: AdrType) {
        this.view.setUint32(16, type, false); // type, bytes 16..19
        this.buf.fill(0, 20); // zero bytes 20..31 (everything after type)
    }

    setKeyPairAddress(idx: number) {
        this.view.setUint32(20, idx >>> 0, false);
    }

    getKeyPairAddress(): number {
        return this.view.getUint32(20, false);
    }

    // WOTS_HASH: chain address (word 2, bytes 24..27)
    setChainAddress(idx: number) {
        this.view.setUint32(24, idx >>> 0, false);
    }

    // WOTS_HASH: hash address (word 3, bytes 28..31)
    setHashAddress(idx: number) {
        this.view.setUint32(28, idx >>> 0, false);
    }

    // TREE: node height (same word as chain address, bytes 24..27)
    setTreeHeight(h: number) {
        this.view.setUint32(24, h >>> 0, false);
    }

    // TREE: node index (same word as hash address, bytes 28..31)
    setTreeIndex(i: number) {
        this.view.setUint32(28, i >>> 0, false);
    }

    getTreeIndex(): number {
        return this.view.getUint32(28, false);
    }

    bytes(): Uint8Array {
        return this.buf.slice();
    }

    copy(): ADRS {
        const a = new AdrsDefault();
        a.buf.set(this.buf);
        return a;
    }
}