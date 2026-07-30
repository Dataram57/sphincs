import {
    // SHA-2
    slh_dsa_sha2_128s as other_sha2_128s,
    slh_dsa_sha2_128f as other_sha2_128f,
    slh_dsa_sha2_192s as other_sha2_192s,
    slh_dsa_sha2_192f as other_sha2_192f,
    slh_dsa_sha2_256s as other_sha2_256s,
    slh_dsa_sha2_256f as other_sha2_256f,

    // SHAKE
    slh_dsa_shake_128s as other_shake_128s,
    slh_dsa_shake_128f as other_shake_128f,
    slh_dsa_shake_192s as other_shake_192s,
    slh_dsa_shake_192f as other_shake_192f,
    slh_dsa_shake_256s as other_shake_256s,
    slh_dsa_shake_256f as other_shake_256f,
    
    // misc
    NAME as OTHER_NAME,
} from "./api.js";

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

const THIS_NAME = "THIS_PACKAGE";

const message = stringToUint8Array("Hello Sphincs");

//testing
function logTest(name: string, expect : boolean, result: boolean ){
    console.log(
        name,
        (expect === result) ? "✅" : "❌" 
    );
}

let dr57 : any;
let other : any;
function testSignatureVerification(name : string, signature : Uint8Array, publicKey : Uint8Array, isSignatureCorrect : boolean){
    console.log(name);
    console.log("Signature length:", signature.length);
    logTest(`Signature - ${THIS_NAME} verifier`, isSignatureCorrect, dr57.verify(message, publicKey, signature));
    logTest(`Signature - ${OTHER_NAME} verifier`, isSignatureCorrect, other.verify(message, publicKey, signature));
}



function testScheme(title : string, _dr57 : any, _other : any){
    console.log("Testing:", title);
    dr57 = _dr57;
    other = _other;

    //My key pair
    const keyPair = dr57.keygen();

    testSignatureVerification(
        `Veryfing ${THIS_NAME} signature signed by ${THIS_NAME} keys`,
        dr57.sign(message, keyPair.secretKey),
        keyPair.publicKey,
        true
    );
    testSignatureVerification(
        `Veryfing ${OTHER_NAME} signature signed by ${THIS_NAME} keys`,
        other.sign(message, keyPair.secretKey),
        keyPair.publicKey,
        true
    );
    //Other key pair
    const otherKeyPair = other.keygen();
    testSignatureVerification(
        `Veryfing ${THIS_NAME} signature signed by ${OTHER_NAME} keys`,
        dr57.sign(message, otherKeyPair.secretKey),
        otherKeyPair.publicKey,
        true
    );
    testSignatureVerification(
        `Veryfing ${OTHER_NAME} signature signed by ${OTHER_NAME} keys`,
        other.sign(message, otherKeyPair.secretKey),
        otherKeyPair.publicKey,
        true
    );
    //Wrong public key
    testSignatureVerification(
        `Veryfing ${THIS_NAME} signature signed by ${THIS_NAME} keys against ${OTHER_NAME} wrong keys`,
        dr57.sign(message, keyPair.secretKey),
        otherKeyPair.publicKey,
        false
    );
    testSignatureVerification(
        `Veryfing ${OTHER_NAME} signature signed by ${THIS_NAME} keys against ${OTHER_NAME} wrong keys`,
        other.sign(message, keyPair.secretKey),
        otherKeyPair.publicKey,
        false
    );
    //Other Wrong public key
    testSignatureVerification(
        `Veryfing ${THIS_NAME} signature signed by ${OTHER_NAME} keys against ${THIS_NAME} wrong keys`,
        dr57.sign(message, otherKeyPair.secretKey),
        keyPair.publicKey,
        false
    );
    testSignatureVerification(
        `Veryfing ${OTHER_NAME} signature signed by ${OTHER_NAME} keys against ${THIS_NAME} wrong keys`,
        other.sign(message, otherKeyPair.secretKey),
        keyPair.publicKey,
        false
    );
}


testScheme("SHA2-128s", dr57_sha2_128s, other_sha2_128s);
testScheme("SHA2-128f", dr57_sha2_128f, other_sha2_128f);
testScheme("SHA2-192s", dr57_sha2_192s, other_sha2_192s);
testScheme("SHA2-192f", dr57_sha2_192f, other_sha2_192f);
testScheme("SHA2-256s", dr57_sha2_256s, other_sha2_256s);
testScheme("SHA2-256f", dr57_sha2_256f, other_sha2_256f);

testScheme("SHAKE-128s", dr57_shake_128s, other_shake_128s);
testScheme("SHAKE-128f", dr57_shake_128f, other_shake_128f);
testScheme("SHAKE-192s", dr57_shake_192s, other_shake_192s);
testScheme("SHAKE-192f", dr57_shake_192f, other_shake_192f);
testScheme("SHAKE-256s", dr57_shake_256s, other_shake_256s);
testScheme("SHAKE-256f", dr57_shake_256f, other_shake_256f);