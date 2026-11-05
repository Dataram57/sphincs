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
} from "../../src/index.js";

import { testScheme } from "../common.js";

const THIS_NAME = "THIS_PACKAGE";

testScheme("SHA2-128s", slh_dsa_sha2_128s, other_sha2_128s, THIS_NAME, OTHER_NAME);
testScheme("SHA2-128f", slh_dsa_sha2_128f, other_sha2_128f, THIS_NAME, OTHER_NAME);
testScheme("SHA2-192s", slh_dsa_sha2_192s, other_sha2_192s, THIS_NAME, OTHER_NAME);
testScheme("SHA2-192f", slh_dsa_sha2_192f, other_sha2_192f, THIS_NAME, OTHER_NAME);
testScheme("SHA2-256s", slh_dsa_sha2_256s, other_sha2_256s, THIS_NAME, OTHER_NAME);
testScheme("SHA2-256f", slh_dsa_sha2_256f, other_sha2_256f, THIS_NAME, OTHER_NAME);

testScheme("SHAKE-128s", slh_dsa_shake_128s, other_shake_128s, THIS_NAME, OTHER_NAME);
testScheme("SHAKE-128f", slh_dsa_shake_128f, other_shake_128f, THIS_NAME, OTHER_NAME);
testScheme("SHAKE-192s", slh_dsa_shake_192s, other_shake_192s, THIS_NAME, OTHER_NAME);
testScheme("SHAKE-192f", slh_dsa_shake_192f, other_shake_192f, THIS_NAME, OTHER_NAME);
testScheme("SHAKE-256s", slh_dsa_shake_256s, other_shake_256s, THIS_NAME, OTHER_NAME);
testScheme("SHAKE-256f", slh_dsa_shake_256f, other_shake_256f, THIS_NAME, OTHER_NAME);