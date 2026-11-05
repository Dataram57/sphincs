export interface ToolSet {
    local:{
        name: string,
        tool: any
    },
    other:{
        name: string,
        tool: any
    }
}

export function stringToUint8Array(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

//testing
function logTest(name: string, expect : boolean, result: boolean ){
    console.log(
        name,
        (expect === result) ? "✅" : "❌" 
    );
}

function testSignatureVerification(
    toolSet: ToolSet,
    name: string,
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
    isSignatureCorrect: boolean
) {
    console.log(name);
    console.log("Signature length:", signature.length);

    // Local verifier
    try {
        const result = toolSet.local.tool.verify(
            message, publicKey, signature
        );

        logTest(
            `Signature - ${toolSet.local.name} verifier`,
            isSignatureCorrect,
            result
        );
    } catch (error) {
        logTest(
            `Signature - ${toolSet.local.name} verifier (exception)`,
            isSignatureCorrect,
            false
        );
    }

    // Reference verifier
    try {
        const result = toolSet.other.tool.verify(
            message, publicKey, signature
        );

        logTest(
            `Signature - ${toolSet.other.name} verifier`,
            isSignatureCorrect,
            result
        );
    } catch (error) {
        logTest(
            `Signature - ${toolSet.other.name} verifier (exception)`,
            isSignatureCorrect,
            false
        );
    }
}



export function testScheme(
    title : string,
    thisSphincs : any, otherSphincs : any, THIS_NAME : string, OTHER_NAME : string,
){
    console.log("Testing:", title);
    const message : Uint8Array = stringToUint8Array("Hello Sphincs");

    const toolSet : ToolSet = {
        local: {
            tool: thisSphincs,
            name: THIS_NAME,
        },
        other: {
            tool: otherSphincs,
            name: OTHER_NAME
        }
    };

    //================================================================
    //This keygen

    const keyPair = thisSphincs.keygen();
    testSignatureVerification(
        toolSet,
        `1.1. Veryfing ${THIS_NAME} signature signed by ${THIS_NAME} keys`,
        message,
        thisSphincs.sign(message, keyPair.secretKey),
        keyPair.publicKey,
        true
    );
    testSignatureVerification(
        toolSet,
        `1.2. Veryfing ${OTHER_NAME} signature signed by ${THIS_NAME} keys`,
        message,
        otherSphincs.sign(message, keyPair.secretKey),
        keyPair.publicKey,
        true
    );
    
    //================================================================
    //Other keygen

    const otherKeyPair = otherSphincs.keygen();
    testSignatureVerification(
        toolSet,
        `2.1. Veryfing ${THIS_NAME} signature signed by ${OTHER_NAME} keys`,
        message,
        thisSphincs.sign(message, otherKeyPair.secretKey),
        otherKeyPair.publicKey,
        true
    );
    testSignatureVerification(
        toolSet,
        `2.2. Veryfing ${OTHER_NAME} signature signed by ${OTHER_NAME} keys`,
        message,
        otherSphincs.sign(message, otherKeyPair.secretKey),
        otherKeyPair.publicKey,
        true
    );
    
    //================================================================
    //Wrong public key

    testSignatureVerification(
        toolSet,
        `3.1. Veryfing ${THIS_NAME} signature signed by ${THIS_NAME} keys against ${OTHER_NAME} wrong keys`,
        message,
        thisSphincs.sign(message, keyPair.secretKey),
        otherKeyPair.publicKey,
        false
    );
    testSignatureVerification(
        toolSet,
        `3.2. Veryfing ${OTHER_NAME} signature signed by ${THIS_NAME} keys against ${OTHER_NAME} wrong keys`,
        message,
        otherSphincs.sign(message, keyPair.secretKey),
        otherKeyPair.publicKey,
        false
    );
    
    //================================================================
    //Other wrong public key

    testSignatureVerification(
        toolSet,
        `4.1. Veryfing ${THIS_NAME} signature signed by ${OTHER_NAME} keys against ${THIS_NAME} wrong keys`,
        message,
        thisSphincs.sign(message, otherKeyPair.secretKey),
        keyPair.publicKey,
        false
    );
    testSignatureVerification(
        toolSet,
        `4.2. Veryfing ${OTHER_NAME} signature signed by ${OTHER_NAME} keys against ${THIS_NAME} wrong keys`,
        message,
        otherSphincs.sign(message, otherKeyPair.secretKey),
        keyPair.publicKey,
        false
    );

    //================================================================
    //Tampered message
    
    const messageTampered : Uint8Array = new Uint8Array(message);
    messageTampered[4]++;

    // Generate reference signature
    const referenceSignature = thisSphincs.sign(
        message,
        keyPair.secretKey
    );

    testSignatureVerification(
        toolSet,
        `5. Veryfing ${THIS_NAME} signature by ${THIS_NAME} keys against tampered message`,
        messageTampered,
        referenceSignature,
        keyPair.publicKey,
        false
    );

    //================================================================
    //Modified signature
    
    const signatureTampered = new Uint8Array(referenceSignature);
    signatureTampered[0] ^= 0x01;

    testSignatureVerification(
        toolSet,
        `6. Veryfing modified ${THIS_NAME} signature by ${THIS_NAME} keys`,
        message,
        signatureTampered,
        keyPair.publicKey,
        false
    );

    //================================================================
    //Truncated signature

    const signatureTruncated = referenceSignature.slice(
        0,
        referenceSignature.length - 1
    );

    testSignatureVerification(
        toolSet,
        `7. Veryfing truncated ${THIS_NAME} signature by ${THIS_NAME} keys`,
        message,
        signatureTruncated,
        keyPair.publicKey,
        false
    );

    //================================================================
    //Empty signature
    
    testSignatureVerification(
        toolSet,
        `8. Veryfing empty ${THIS_NAME} signature by ${THIS_NAME} keys`,
        message,
        new Uint8Array(0),
        keyPair.publicKey,
        false
    );

    //================================================================
    //signature of another message 

    // Signature generated for another message
    const anotherMessage = stringToUint8Array("Another message");

    const anotherSignature = thisSphincs.sign(
        anotherMessage,
        keyPair.secretKey
    );

    testSignatureVerification(
        toolSet,
        `9. Veryfing different ${THIS_NAME} signature by ${THIS_NAME} keys`,
        message,
        anotherSignature,
        keyPair.publicKey,
        false
    );

}