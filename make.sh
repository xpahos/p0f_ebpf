#!/bin/bash
#clang-6.0 \
#    -I "/usr/src/linux-headers-$(uname -r)/include/" -I "/usr/src/linux-headers-$(uname -r)/arch/x86/include/" \
#    -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
#    -Wno-gnu-variable-sized-type-not-at-end \
#    -Wno-address-of-packed-member -Wno-tautological-compare \
#    -Wno-unknown-warning-option \
#    -O2 -target bpf -emit-llvm -c bpf_prog.c -o - | llc-6.0 -march=bpf -filetype=obj -o bpf_prog.o

gcc main.c libbpf.c bpf_load.c -lelf
