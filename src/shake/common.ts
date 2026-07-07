import { createHash } from "node:crypto";

export function shake256(n: number, ...chunks: Uint8Array[]): Uint8Array {
    const h = createHash("shake256", { outputLength: n });
    for (const c of chunks) {
        h.update(c);
    }
    return new Uint8Array(h.digest());
}
