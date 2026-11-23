#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
#
# pack.sh: obj/PROJECT/TARGET/*.bpf.o -> obj/NAME.COMPILER.tar.zst
# All releases of a large project are in one archive. The small projects are in 'others'.
cd "$(dirname "$0")/../obj" || exit 1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Objects with the same name are next to each other. That compresses best.
find . -name '*.bpf.o' -printf '%P\n' | awk -F/ -v tmp="$tmp" '{
	name = $1; sub(/-v?[0-9]+\..*/, "", name)
	if (name !~ /^(cilium|datadog-agent|falco-libs|linux|scx|tetragon|tracee)$/) name = "others"
	if (match($1, /^datadog-agent-7\.[0-9]/)) name = substr($1, 1, RLENGTH) "x"
	split($2, t, "-"); obj = substr($3, length($1) + 2)
	print (name == "others" ? $1 : "") obj "\t" $0 > (tmp "/" name "." t[1] "-" t[2]) }'
ls "$tmp" | xargs -P "${JOBS:-8}" -I{} sh -c "LC_ALL=C sort $tmp/{} | cut -f2 |
	tar -cf - --owner=0 --group=0 --mode=644 --mtime=@0 -T - | zstd -q -f -19 --long=27 -T8 -o {}.tar.zst"
