#! /bin/bash
rm -rf ebpf-verifier
git clone https://github.com/vbpf/ebpf-verifier.git --recursive
cd ebpf-verifier && rm -rf .git && cd -