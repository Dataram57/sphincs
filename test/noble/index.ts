import {
    // SHA-2
    slh_dsa_sha2_128s as noble_sha2_128s,
    slh_dsa_sha2_128f as noble_sha2_128f,
    slh_dsa_sha2_192s as noble_sha2_192s,
    slh_dsa_sha2_192f as noble_sha2_192f,
    slh_dsa_sha2_256s as noble_sha2_256s,
    slh_dsa_sha2_256f as noble_sha2_256f,

    // SHAKE
    slh_dsa_shake_128s as noble_shake_128s,
    slh_dsa_shake_128f as noble_shake_128f,
    slh_dsa_shake_192s as noble_shake_192s,
    slh_dsa_shake_192f as noble_shake_192f,
    slh_dsa_shake_256s as noble_shake_256s,
    slh_dsa_shake_256f as noble_shake_256f,
} from "@noble/post-quantum/slh-dsa.js";

import {
    // SHA-2
    slh_dsa_sha2_128s as dr57_sha2_128s,
    slh_dsa_sha2_128f as dr57_sha2_128f,
    slh_dsa_sha2_192s as dr57_sha2_192s,
    slh_dsa_sha2_192f as dr57_sha2_192f,
    slh_dsa_sha2_256s as dr57_sha2_256s,
    slh_dsa_sha2_256f as dr57_sha2_256f,

    // SHAKE
    slh_dsa_shake_128s as dr57_shake_128s,
    slh_dsa_shake_128f as dr57_shake_128f,
    slh_dsa_shake_192s as dr57_shake_192s,
    slh_dsa_shake_192f as dr57_shake_192f,
    slh_dsa_shake_256s as dr57_shake_256s,
    slh_dsa_shake_256f as dr57_shake_256f,
} from "../../src/index.js";


function stringToUint8Array(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

const message = stringToUint8Array("Hello Sphincs");

//testing
function logTest(name: string, expect : boolean, result: boolean ){
    console.log(
        name,
        (expect === result) ? "✅" : "❌" 
    );
}

let dr57 : any;
let noble : any;
function testSignatureVerification(name : string, signature : Uint8Array, publicKey : Uint8Array, isSignatureCorrect : boolean){
    console.log(name);
    console.log("Signature length:", signature.length);
    logTest("Signature - My verifier", isSignatureCorrect, dr57.verify(message, publicKey, signature));
    logTest("Signature - Noble verifier", isSignatureCorrect, noble.verify(signature, message, publicKey));
}



function testScheme(title : string, _dr57 : any, _noble : any){
    console.log("Testing:", title);
    dr57 = _dr57;
    noble = _noble;

    //My key pair
    const keyPair = dr57.keygen();

    testSignatureVerification(
        "Veryfing MY signature signed by MY keys",
        dr57.sign(message, keyPair.secretKey),
        keyPair.publicKey,
        true
    );
    testSignatureVerification(
        "Veryfing NOBLE signature signed by MY keys",
        noble.sign(message, keyPair.secretKey),
        keyPair.publicKey,
        true
    );
    //Noble key pair
    const nobleKeyPair = noble.keygen();
    testSignatureVerification(
        "Veryfing MY signature signed by NOBLE keys",
        dr57.sign(message, nobleKeyPair.secretKey),
        nobleKeyPair.publicKey,
        true
    );
    testSignatureVerification(
        "Veryfing NOBLE signature signed by NOBLE keys",
        noble.sign(message, nobleKeyPair.secretKey),
        nobleKeyPair.publicKey,
        true
    );
    //Wrong public key
    testSignatureVerification(
        "Veryfing MY signature signed by MY keys against NOBLE wrong keys",
        dr57.sign(message, keyPair.secretKey),
        nobleKeyPair.publicKey,
        false
    );
    testSignatureVerification(
        "Veryfing NOBLE signature signed by MY keys against NOBLE wrong keys",
        noble.sign(message, keyPair.secretKey),
        nobleKeyPair.publicKey,
        false
    );
    //Noble Wrong public key
    testSignatureVerification(
        "Veryfing MY signature signed by NOBLE keys against MY wrong keys",
        dr57.sign(message, nobleKeyPair.secretKey),
        keyPair.publicKey,
        false
    );
    testSignatureVerification(
        "Veryfing NOBLE signature signed by NOBLE keys against MY wrong keys",
        noble.sign(message, nobleKeyPair.secretKey),
        keyPair.publicKey,
        false
    );
}

testScheme("SHA2-128s", dr57_sha2_128s, noble_sha2_128s);
testScheme("SHA2-128f", dr57_sha2_128f, noble_sha2_128f);
testScheme("SHA2-192s", dr57_sha2_192s, noble_sha2_192s);
testScheme("SHA2-192f", dr57_sha2_192f, noble_sha2_192f);
testScheme("SHA2-256s", dr57_sha2_256s, noble_sha2_256s);
testScheme("SHA2-256f", dr57_sha2_256f, noble_sha2_256f);

testScheme("SHAKE-128s", dr57_shake_128s, noble_shake_128s);
testScheme("SHAKE-128f", dr57_shake_128f, noble_shake_128f);
testScheme("SHAKE-192s", dr57_shake_192s, noble_shake_192s);
testScheme("SHAKE-192f", dr57_shake_192f, noble_shake_192f);
testScheme("SHAKE-256s", dr57_shake_256s, noble_shake_256s);
testScheme("SHAKE-256f", dr57_shake_256f, noble_shake_256f);