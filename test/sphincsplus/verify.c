#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "api.h"

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex2bin(const char *hex, uint8_t *out, size_t outlen)
{
    if (strlen(hex) != outlen * 2)
        return -1;

    for (size_t i = 0; i < outlen; i++) {
        int hi = hexval(hex[2 * i]);
        int lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <message> <public-key-hex> <signature-hex>\n",
            argv[0]);
        return 1;
    }

    const uint8_t *msg = (const uint8_t *)argv[1];
    size_t msglen = strlen(argv[1]);

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    if (hex2bin(argv[2], pk, sizeof(pk)) != 0) {
        fprintf(stderr,
                "Public key must be %zu bytes (%zu hex characters)\n",
                (size_t)CRYPTO_PUBLICKEYBYTES,
                (size_t)CRYPTO_PUBLICKEYBYTES * 2);
        return 1;
    }

    uint8_t sig[CRYPTO_BYTES];
    if (hex2bin(argv[3], sig, sizeof(sig)) != 0) {
        fprintf(stderr,
                "Signature must be %zu bytes (%zu hex characters)\n",
                (size_t)CRYPTO_BYTES,
                (size_t)CRYPTO_BYTES * 2);
        return 1;
    }

    int rc = crypto_sign_verify(
        sig, sizeof(sig),
        msg, msglen,
        NULL, 0,
        pk);

    if (rc == 0) {
        printf("OK\n");
        return 0;
    } else {
        printf("INVALID\n");
        return 1;
    }
}