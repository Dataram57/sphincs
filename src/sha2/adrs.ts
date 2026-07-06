import { ADRS, AdrType } from "../adrs.js";

export class AdrsCompressed implements ADRS {
    buf = new Uint8Array(22);
    private view = new DataView(this.buf.buffer);

    setLayerAddress(layer: number) {
        this.buf[0] = layer;
    }

    setTreeAddress(tree: bigint) {
        this.view.setBigUint64(1, tree, false); // BE, bytes 1..8
    }

    setTypeAndClear(type: AdrType) {
        this.buf[9] = type;
        this.buf.fill(0, 10); // zero bytes 10..21
    }

    setKeyPairAddress(idx: number) {
        this.buf[13] = idx & 0xff;
    }

    getKeyPairAddress(): number {
        return this.buf[13];
    }

    // WOTS_HASH: chain address
    setChainAddress(idx: number) {
        this.buf[17] = idx;
    }

    // WOTS_HASH: hash address (byte 21)
    setHashAddress(idx: number) {
        this.buf[21] = idx;
    }

    // TREE: node height (same byte as chain)
    setTreeHeight(h: number) {
        this.buf[17] = h;
    }

    // TREE: node index (uint32 BE at offset 18)
    setTreeIndex(i: number) {
        this.view.setUint32(18, i >>> 0, false);
    }

    getTreeIndex(): number {
        return this.view.getUint32(18, false);
    }

    bytes(): Uint8Array {
        return this.buf.slice();
    }

    copy(): ADRS {
        const a = new AdrsCompressed();
        a.buf.set(this.buf);
        return a;
    }
}