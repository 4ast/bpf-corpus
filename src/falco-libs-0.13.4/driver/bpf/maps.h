/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __MAPS_H
#define __MAPS_H

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};

#ifdef __KERNEL__
#ifndef __uint
#define __uint(name, val) int(*name)[val]
#endif
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 0);
} perf_map __bpf_section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, PPM_FILLER_MAX);
} tail_map __bpf_section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct syscall_evt_pair));
	__uint(max_entries, SYSCALL_TABLE_SIZE);
} syscall_table __bpf_section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct ppm_event_info));
	__uint(max_entries, PPM_EVENT_MAX);
} event_info_table __bpf_section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct ppm_event_entry));
	__uint(max_entries, PPM_EVENT_MAX);
} fillers_table __bpf_section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, SCRATCH_SIZE);
	__uint(max_entries, 0);
} frame_scratch_map __bpf_section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, SCRATCH_SIZE);
	__uint(max_entries, 0);
} tmp_scratch_map __bpf_section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct scap_bpf_settings));
	__uint(max_entries, 1);
} settings_map __bpf_section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct scap_bpf_per_cpu_state));
	__uint(max_entries, 0);
} local_state_map __bpf_section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(bool));
	__uint(max_entries, SYSCALL_TABLE_SIZE);
} interesting_syscalls_table __bpf_section(".maps");

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct sys_stash_args));
	__uint(max_entries, 65535);
} stash_map __bpf_section(".maps");
#endif

#endif // __KERNEL__

#endif
/* Changed for bpf-corpus in 2026-11, see CHANGES.diff in the top directory of the project. */
