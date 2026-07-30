//execution
import { execFileSync } from "node:child_process";

//
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
const __dirname = dirname(fileURLToPath(import.meta.url));
const BUILD_DIR = join(__dirname, "build");
//check if variants are not built
if(!existsSync(join(BUILD_DIR, "sphincs-shake-256s/verify")))
    throw "sphincsplus binaries couldn't be found. Please run `./setup.sh` first, or read related `README.MD` to get more information.";


export const NAME = "SPHINCSPLUS (bas/fips205)";
export interface Sphincs {
  keygen(): {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  };

  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;

  verify(
    message: Uint8Array,
    publicKey: Uint8Array,
    signature: Uint8Array,
  ): boolean;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function getSphincs(name: string): Sphincs {
  const dir = join(BUILD_DIR, name);

  const run = (program: string, args: readonly string[]) =>
    execFileSync(`${dir}/${program}`, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();

  return Object.freeze({
    keygen() {
      const output = run("keygen", []);

      const pk = output.match(/^Public key:(.+)$/m);
      const sk = output.match(/^Secret key:(.+)$/m);

      if (!pk || !sk) {
        throw new Error(`Unexpected keygen output:\n${output}`);
      }

      return {
        publicKey: hexToBytes(pk[1]),
        secretKey: hexToBytes(sk[1]),
      };
    },

    sign(message : Uint8Array, secretKey : Uint8Array) {
      const sig = run("sign", [
        bytesToHex(secretKey),
        Buffer.from(message).toString("utf8"),
      ]);

      return hexToBytes(sig);
    },

    verify(message : Uint8Array, publicKey : Uint8Array, signature : Uint8Array) {
        try {
        const out = run("verify", [
          Buffer.from(message).toString("utf8"),
          bytesToHex(publicKey),
          bytesToHex(signature),
        ]);
        return out === "OK";
      } catch(exception : any) {
        //console.log(exception);
        // verify exits non-zero on invalid signatures
        return false;
      }
    },
  });
}

export const slh_dsa_sha2_128s = getSphincs("sphincs-sha2-128s");
export const slh_dsa_sha2_128f = getSphincs("sphincs-sha2-128f");
export const slh_dsa_sha2_192s = getSphincs("sphincs-sha2-192s");
export const slh_dsa_sha2_192f = getSphincs("sphincs-sha2-192f");
export const slh_dsa_sha2_256s = getSphincs("sphincs-sha2-256s");
export const slh_dsa_sha2_256f = getSphincs("sphincs-sha2-256f");

export const slh_dsa_shake_128s = getSphincs("sphincs-shake-128s");
export const slh_dsa_shake_128f = getSphincs("sphincs-shake-128f");
export const slh_dsa_shake_192s = getSphincs("sphincs-shake-192s");
export const slh_dsa_shake_192f = getSphincs("sphincs-shake-192f");
export const slh_dsa_shake_256s = getSphincs("sphincs-shake-256s");
export const slh_dsa_shake_256f = getSphincs("sphincs-shake-256f");