/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Tetragon since v1.7 generates cel_expr_N() from the tracing policy and links
 * them in at load time. These stubs stand for a policy with no expression.
 */
#ifndef CEL_RET
#define CEL_RET long long
#endif
#define CEL_STUB(n) \
	__attribute__((weak, noinline)) CEL_RET cel_expr_##n(long *argsoff, char *args) { return 0; }
CEL_STUB(0) CEL_STUB(1) CEL_STUB(2) CEL_STUB(3) CEL_STUB(4) CEL_STUB(5) CEL_STUB(6) CEL_STUB(7)
