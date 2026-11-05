import {
    // SHA-2
    slh_dsa_sha2_128s,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_192s,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_256s,
    slh_dsa_sha2_256f,

    // SHAKE
    slh_dsa_shake_128s,
    slh_dsa_shake_128f,
    slh_dsa_shake_192s,
    slh_dsa_shake_192f,
    slh_dsa_shake_256s,
    slh_dsa_shake_256f
} from "../src/index.js";
import { appendFileSync, writeFileSync } from "node:fs";


function measureFunction(
    title : string,
    iterCount : number,
    func : () => void
) {
    console.log(`Starting ${title}, ${iterCount} times`);
    appendFileSync(RESULTS_FILEPATH, title + ";", "utf-8");
    let timeStart : bigint; 
    let timeEnd : bigint;
    const result : bigint[] = new Array<bigint>(iterCount);
    while(iterCount--){
        timeStart = process.hrtime.bigint();
        func();
        timeEnd = process.hrtime.bigint();
        result[iterCount] = timeEnd - timeStart;
    }
    //save to file
    console.log(`Saving ${result.length} samples`);
    const line = result.reverse().map(String).join(";") + "\n";
    appendFileSync(RESULTS_FILEPATH, line, "utf-8");
}


//these numbers shoud be based on appropiate standard deviation
const KEYGEN_SAMPLE_COUNT = 30;
const SIGN_SAMPLE_COUNT = 30;
const VERIFY_SAMPLE_COUNT = 30;
const MESSAGE = new TextEncoder().encode("Hello Sphincs Benchmark!!!");
const RESULTS_FILEPATH = "./results.csv";

function measureLocalSphincs(title : string, scheme : any){
    measureFunction(
        `${title} - keygen`,
        KEYGEN_SAMPLE_COUNT,
        scheme.keygen
    );

    const keys = scheme.keygen();

    measureFunction(
        `${title} - sign`,
        SIGN_SAMPLE_COUNT,
        () => {
            scheme.sign(MESSAGE, keys.secretKey);
        }
    );

    const signature = scheme.sign(MESSAGE, keys.secretKey);

    measureFunction(
        `${title} - verify`,
        VERIFY_SAMPLE_COUNT,
        () => {
            scheme.verify(MESSAGE, keys.publicKey, signature);
        }
    );
    



}

//clean results
writeFileSync(RESULTS_FILEPATH, "");

//sha2
measureLocalSphincs("sha2-128s", slh_dsa_sha2_128s);
measureLocalSphincs("sha2-128f", slh_dsa_sha2_128f);
measureLocalSphincs("sha2-192s", slh_dsa_sha2_192s);
measureLocalSphincs("sha2-192f", slh_dsa_sha2_192f);
measureLocalSphincs("sha2-256s", slh_dsa_sha2_256s);
measureLocalSphincs("sha2-256f", slh_dsa_sha2_256f);

//shake
measureLocalSphincs("shake-128s", slh_dsa_shake_128s);
measureLocalSphincs("shake-128f", slh_dsa_shake_128f);
measureLocalSphincs("shake-192s", slh_dsa_shake_192s);
measureLocalSphincs("shake-192f", slh_dsa_shake_192f);
measureLocalSphincs("shake-256s", slh_dsa_shake_256s);
measureLocalSphincs("shake-256f", slh_dsa_shake_256f);