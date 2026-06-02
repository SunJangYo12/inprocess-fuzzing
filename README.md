Running fuzz after target function is hit. This fuzzer use backend frida-gum

### Linux

```sh
cargo build
LD_PRELOAD=./target/debug/libfuzz_inprocess.so ./test
nc localhost 7777
```

