#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
#
# run.sh OUT.csv [DIR|OBJECT..]: load the objects with veristat on all CPUs, as root.
# The default is all of obj/. Compare two kernels with: ./compare.py old.csv new.csv
out=${1:?usage: run.sh OUT.csv [DIR|OBJECT..]}
shift
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
ulimit -l unlimited -n 65536 2> /dev/null
# The largest objects start first.
find "${@:-$(dirname "$0")/obj}" -name '*.bpf.o' -printf '%s %p\n' | sort -rn | cut -d' ' -f2- |
	xargs -d '\n' -P "${JOBS:-$(nproc)}" -n 4 sh -c \
	'${VERISTAT:-veristat} -q -o csv -e file,prog,verdict,duration,insns,states,peak_states \
		"$@" 2> /dev/null > $(mktemp -p '$tmp')' sh
{ head -q -n 1 "$tmp"/* | sort -u | grep ^file_name; cat "$tmp"/* | grep -v ^file_name | sort; } > "$out"
awk -F, 'NR > 1 { n++; ok += $3 == "success"; env += $3 != "success" && !$5 }
	END { printf "%d programs, %d load, %d did not get to the verifier\n", n, ok, env }' "$out"
