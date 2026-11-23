#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
#
# unpack.sh [GLOB..]: unpack the archives of obj/ whose names match, the default is all
#   ./unpack.sh 'cilium*' '*clang-20*'
cd "$(dirname "$0")/obj" || exit 1
for g in "${@:-*}"; do
	find . -maxdepth 1 -name "${g%.tar.zst}.tar.zst" -o -maxdepth 1 -name "$g.*.tar.zst"
done | sort -u | xargs -r -P "$(nproc)" -n 1 tar --zstd -xf
