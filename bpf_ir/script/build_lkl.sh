
# build lkl
make ARCH=lkl CC=clang AS=llvm-as-10 mrproper
pushd tools/lkl && make CC=clang AS=llvm-as-10 clean-conf && popd
pushd tools/lkl && make CC=clang ARCH=lkl AR=llvm-ar AS=llvm-as-10 -j12 dpdk=no && popd

make ARCH=lkl CC=afl-clang-fast mrproper
pushd tools/lkl && make CC=afl-clang-fast clean-conf && popd
pushd tools/lkl && make CC=afl-clang-fast ARCH=lkl -j12 dpdk=no && popd

make LLVM=1 LLVM_IAS=1 AS=llvm-as-10 CC=clang ARCH=lkl mrproper
# Load the default config
make LLVM=1 LLVM_IAS=1 AS=llvm-as-10 CC=clang ARCH=lkl defconfig
# Edit the configuration
make LLVM=1 LLVM_IAS=1 AS=llvm-as-10 CC=clang ARCH=lkl menuconfig
cp .config arch/lkl/configs/defconfig
make AFL_AS=llvm-as-10 AS=llvm-as-10 LLVM=1 LLVM_IAS=1 CC=clang ARCH=lkl -C tools/lkl


# clean lkl
make clean
make -C tools/lkl clean