
### Quick one liner

`sha2-128f` example:

```sh
eval "$(./build/sphincs-sha2-128f/keygen | awk -F: '/Public key/{print "PK="$2} /Secret key/{print "SK="$2}')" && SIG=$(./build/sphincs-sha2-128f/sign "$SK" "hello") && ./build/sphincs-sha2-128f/verify "hello" "$PK" "$SIG"
```

It should print `OK` if `keygen`, `sign` and `verify` work.