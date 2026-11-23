/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * The loader of the Datadog agent writes its options into the insns, so the
 * verifier sees one side of each option. With this header an option is a load
 * from a global variable, and the verifier sees both sides.
 * Offsets, sizes, numbers of arguments and options that go with the type of a map
 * or of a program stay constants.
 */
volatile unsigned long long corpus_unknown_option;

#define CORPUS_IS(p, s) !__builtin_strcmp(p, s)
#define CORPUS_HAS(p, s) __builtin_strstr(p, s)

/* kprobes cannot call bpf_sk_storage_get() */
#ifdef CORPUS_NO_SK_STORAGE
#define CORPUS_SK_STORAGE(p) CORPUS_IS(p, "is_sk_storage_supported")
#else
#define CORPUS_SK_STORAGE(p) 0
#endif

#define CORPUS_CONSTANT(p)							\
	(CORPUS_HAS(p, "_offset") || CORPUS_HAS(p, "sizeof_") ||		\
	 CORPUS_HAS(p, "_position") || CORPUS_HAS(p, "_input") ||		\
	 CORPUS_HAS(p, "_arg") || CORPUS_IS(p, "mnt_namespace_ns") ||		\
	 CORPUS_IS(p, "use_ring_buffer") ||					\
	 CORPUS_IS(p, "use_syscall_task_storage") || CORPUS_SK_STORAGE(p))

#define LOAD_CONSTANT(param, var)					\
	do {								\
		if (CORPUS_CONSTANT(param))				\
			asm("%0 = " param " ll" : "=r"(var));		\
		else							\
			(var) = corpus_unknown_option;			\
	} while (0)
