function hexToUint8Array(hex : string) {
    //check odd length error
    if((hex.length & 1) !== 0)
        throw new Error("Hex string must have an even length");
    //convert
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) 
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
}
import {
    slh_dsa_sha2_128f as dr57_sha2_128f,
} from "../src/index.js";


//parse secret key for sha2-128f
const secretKey = hexToUint8Array("4df714200b1303f4188f8a7a55aac309ee58a54e57b6afbadd8a147b331f40312844734418fab04148f7c5b5910392e121db90188360e8c0057812a7ec8a4ba0");

//sign
dr57_sha2_128f.sign(new TextEncoder().encode("hello"), secretKey);
