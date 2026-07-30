# Testing against [`sphincsplus`](https://github.com/sphincs/sphincsplus) (FIPS 205)

> **Note:** All commands in this document should be executed from the directory containing this file.

This package provides tools for basic interaction with the official SPHINCS+ reference implementation.

## [`sphincsplus`](https://github.com/sphincs/sphincsplus) FIPS 205 commit

Check `repo_commit` (or `repo_branch`) file to get specific commit.

## Requirements

- GCC

> **Note:** These tools may also be available through the parent `flake.nix`.

## Setup

To download the official repository and compile all SPHINCS+ variants required for testing, run:

```sh
./setup.sh
```

## Quick executable check

To quickly verify that a specific SPHINCS+ variant (for example, `sha2-128f`) was built correctly, run:

```sh
eval "$(./build/sphincs-sha2-128f/keygen | awk -F: '/Public key/{print "PK="$2} /Secret key/{print "SK="$2}')" && \
SIG=$(./build/sphincs-sha2-128f/sign "$SK" "hello") && \
./build/sphincs-sha2-128f/verify "hello" "$PK" "$SIG"
```

If the `keygen`, `sign`, and `verify` executables are working correctly, the command should print:

```text
OK
```