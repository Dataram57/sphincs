#!/usr/bin/env bash

set -Eeuo pipefail

REPO_URL="https://github.com/sphincs/sphincsplus.git"
REPO_DIR="sphincsplus"
BUILD_DIR="../build"

# Pin to a known revision
COMMIT="ef36d20ff3588324ad69f844507b8217f008f35a"
# Or use:
# BRANCH="bas/fips205"

for tool in git gcc; do
    command -v "$tool" >/dev/null || {
        echo "Error: '$tool' is not installed." >&2
        exit 1
    }
done

if [[ ! -d "$REPO_DIR/.git" ]]; then
    git clone "$REPO_URL" "$REPO_DIR"
fi

cd "$REPO_DIR"

git fetch --all --tags

git checkout "$COMMIT"
# Or:
# git checkout "$BRANCH"

PARAMS=(
    sphincs-sha2-128f
    sphincs-sha2-128s
    sphincs-sha2-192f
    sphincs-sha2-192s
    sphincs-sha2-256f
    sphincs-sha2-256s

    sphincs-shake-128f
    sphincs-shake-128s
    sphincs-shake-192f
    sphincs-shake-192s
    sphincs-shake-256f
    sphincs-shake-256s
)

COMMON_SOURCES=(
    ref/address.c
    ref/randombytes.c
    ref/merkle.c
    ref/wots.c
    ref/wotsx1.c
    ref/utils.c
    ref/utilsx1.c
    ref/fors.c
    ref/sign.c
)

for params in "${PARAMS[@]}"; do
    if [[ "$params" == sphincs-sha2-* ]]; then
        EXTRA=(
            ref/sha2.c
            ref/hash_sha2.c
        )
        FAMILY="sha2"
    elif [[ "$params" == sphincs-shake-* ]]; then
        EXTRA=(
            ref/fips202.c
            ref/hash_shake.c
        )
        FAMILY="shake"
    else
        echo "Unknown parameter set: $params"
        exit 1
    fi

    echo "Building $params..."

    mkdir -p "$BUILD_DIR/$params"

    gcc -O3 -std=c99 \
        -DPARAMS="$params" \
        -DTHASH="simple" \
        -Iref \
        "${COMMON_SOURCES[@]}" \
        "${EXTRA[@]}" \
        "ref/thash_${FAMILY}_simple.c" \
        ../keygen.c \
        -o "$BUILD_DIR/$params/keygen"
done

echo
echo "Done."
echo "Binaries written to:"
echo "  $(realpath "$BUILD_DIR")"