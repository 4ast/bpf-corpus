/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* the kernel has an enumerator with the name of one in systing.h. */
#define ARG_NONE CORPUS_KERNEL_ARG_NONE
#include "../../../include/vmlinux/vmlinux.h"
#undef ARG_NONE
