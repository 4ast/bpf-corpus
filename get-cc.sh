#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
#
# get-cc.sh [NAME..]: put the compilers that made obj/ into cc/NAME
#
#   clang-N   download of the build from kernel.org, x86_64 or aarch64
#   gcc-N     built from the GNU sources, about 10 minutes each
#             needs a C++ compiler, make, flex, bison, gmp, mpfr and mpc
set -e
cd "$(dirname "$0")"
LLVM=https://mirrors.edge.kernel.org/pub/tools/llvm/files
GNU=https://mirrors.kernel.org/gnu
BINUTILS=2.47
declare -A V=(
	[clang-14]=14.0.6 [clang-15]=15.0.7 [clang-16]=16.0.6 [clang-17]=17.0.6
	[clang-18]=18.1.8 [clang-19]=19.1.7 [clang-20]=20.1.8 [clang-21]=21.1.8
	[clang-22]=22.1.8 [clang-23]=23.1.6
	[gcc-14]=14.4.0 [gcc-15]=15.3.0 [gcc-16]=16.2.0
)

fetch() { [ -s "cc/dl/${1##*/}" ] || curl -fL --retry 3 -o "cc/dl/${1##*/}" "$1"; }

get_clang() {
	local f=llvm-${V[$1]}-$(uname -m)
	fetch $LLVM/$f.tar.xz
	tar -C cc -xf cc/dl/$f.tar.xz
	mv cc/$f cc/$1
}

# build SOURCE_DIR PREFIX "MAKE TARGETS" CONFIGURE_ARGS..
build() {
	local src=$PWD/$1 prefix=$PWD/$2 targets=$3 t
	shift 3
	mkdir -p $src.build
	(cd $src.build
	 $src/configure --target=bpf-unknown-none --prefix=$prefix --disable-nls \
		--disable-werror "$@"
	 for t in $targets; do make -j"${JOBS:-$(nproc)}" MAKEINFO=true $t; done)
	rm -rf "$src" "$src.build"
}

get_gcc() {
	local g=gcc-${V[$1]} b=binutils-$BINUTILS
	fetch $GNU/binutils/$b.tar.xz
	fetch $GNU/gcc/$g/$g.tar.xz
	mkdir -p cc/tmp-$1
	tar -C cc/tmp-$1 -xf cc/dl/$b.tar.xz
	# gcc drops __hidden if it finds no ld
	build cc/tmp-$1/$b cc/tmp-$1/out \
		"all-gas all-ld all-binutils install-gas install-ld install-binutils" \
		--disable-gdb --disable-gprofng
	tar -C cc/tmp-$1 -xf cc/dl/$g.tar.xz
	# The BPF backend finds enums with a plugin callback. It crashes with no plugin support.
	PATH=$PWD/cc/tmp-$1/out/bin:$PATH build cc/tmp-$1/$g cc/tmp-$1/out \
		"all-gcc install-gcc" --enable-languages=c --disable-bootstrap \
		--disable-multilib --disable-lto --enable-plugin --without-headers
	mv cc/tmp-$1/out cc/$1
	rmdir cc/tmp-$1
}

mkdir -p cc/dl
for n in ${*:-$(printf '%s\n' "${!V[@]}" | sort -V)}; do
	[ -n "${V[$n]}" ] || { echo "unknown compiler $n"; exit 1; }
	[ -d cc/$n ] && continue
	get_${n%-*} $n
done
