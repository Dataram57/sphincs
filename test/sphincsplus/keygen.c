#include <stdio.h>
#include <stdint.h>
#include "api.h"

static void print_hex(const char *name, const uint8_t *buf, size_t len)
{
    printf("%s:", name);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    print_hex("Public key", pk, sizeof(pk));
    print_hex("Secret key", sk, sizeof(sk));

    return 0;
}
