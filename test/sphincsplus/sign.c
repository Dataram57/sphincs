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

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <secret-key-hex> <message>\n",
            argv[0]);
        return 1;
    }

    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    if (hex2bin(argv[1], sk, sizeof(sk)) != 0) {
        fprintf(stderr,
            "Secret key must be %zu bytes (%zu hex characters)\n",
            (size_t)CRYPTO_SECRETKEYBYTES,
            (size_t)CRYPTO_SECRETKEYBYTES * 2);
        return 1;
    }

    const uint8_t *msg = (const uint8_t *)argv[2];
    size_t msglen = strlen(argv[2]);

    uint8_t sig[CRYPTO_BYTES];
    size_t siglen;

    if (crypto_sign_signature(sig, &siglen,
                          msg, msglen,
                          NULL, 0,
                          sk) != 0) {
        fprintf(stderr, "Signing failed\n");
        return 1;
    }

    print_hex(sig, siglen);

    return 0;
}