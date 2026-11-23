/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* The Makefile of the BPF selftests gives this option to clang for -mcpu=v3 and v4 only. */
#if defined(__clang__) && __BPF_CPU_VERSION__ >= 3
#define ENABLE_ATOMICS_TESTS 1
#endif
