# bpf-corpus

Real BPF programs from 69 open source projects, as C sources and as ELF objects.
Use them to check a change of the verifier, a JIT, libbpf or a compiler.

| project | objects | programs, clang | load | programs, gcc | load |
|---|---:|---:|---:|---:|---:|
| Cilium | 3746 | 79185 | 100% | 10399 | 96% |
| Datadog agent | 8799 | 1060680 | 97% | 4588 | 52% |
| Falco | 242 | 57296 | 90% | 0 | - |
| scx | 614 | 10886 | 92% | 5 | 100% |
| Tetragon | 10842 | 43300 | 94% | 679 | 92% |
| Tracee | 193 | 15810 | 97% | 14 | 100% |
| BPF selftests | 11242 | 55948 | 71% | 29921 | 69% |
| others | 32777 | 154199 | 97% | 21799 | 75% |
| total | 68455 | 1477304 | 96% | 67405 | 74% |

"load" is for bpf-next 2bf3351c5f89.

## Check a verifier change

    ./unpack.sh                    # 24 GB in obj/. A part: ./unpack.sh 'cilium*' '*clang-20*'
    ./run.sh old.csv               # as root, on the kernel without the change
    ./run.sh new.csv               # on the kernel with the change
    ./compare.py old.csv new.csv   # lost and gained programs, changes of insns

`run.sh` needs `veristat` from `tools/testing/selftests/bpf`. Each object loads with plain
`veristat OBJECT`, with no option. Nothing is attached. The names of the files are unique, so
`veristat -C` works too. All objects take 4 minutes on 120 CPUs.

The objects are for x86_64. Build the kernel with clang and with
`tools/testing/selftests/bpf/{config,config.vm,config.x86_64}` and `kernel.config`.
Load `bpf_testmod.ko` for the selftests.

Not all programs load. Some hooks are not in the kernel any more, many selftests must fail, and
a project supports only some compilers. Always compare two runs.
`results/` has the run on the commit of `linux` in `projects.tsv`, and the list of the objects
that a compiler refuses.

## Build

    ./get-cc.sh                            # clang 14..23 from kernel.org, gcc 14..16 from source
    ./build.py                             # what the file 'matrix' says
    ./build.py -t 'clang-20-v?' tetragon   # -mcpu=v2, v3 and v4
    ./build.py -c clang-git=/llvm/bin/clang -t 'clang-git-*' 'bcc/tcp*'

The build needs python3 and a compiler. It reads no header of the host and runs no build system
of a project. Objects that are linked from many files (Falco, scx, wprof) need `bpftool`.

A target is `COMPILER-CPU[-FLAVOUR]`:

| flavour | flags |
|---|---|
| none | `-O2` |
| O1, Os, O3 | the optimization level |
| pl | `always_inline` is dropped, the compiler decides |
| ni | `always_inline` becomes `noinline` |
| nc | the values of `const volatile` options are not known to the verifier |

## Layout

| path | content |
|---|---|
| `projects.tsv` | URL, commit and licence of each project |
| `src/PROJECT/` | only the files that a compiler reads, at the paths of the project |
| `src/PROJECT/jobs` | one line per object: sources, flags, fixups |
| `src/PROJECT/CHANGES.diff` | the changes against the project |
| `include/` | libbpf, vmlinux.h, kernel and libc headers |
| `tools/fixup.py` | does in the object what the loader of a project does at load time |
| `obj/` | `PROJECT/TARGET/PROJECT.OBJECT.TARGET.bpf.o`, in archives per compiler |

`OBJECT@x` has another attach target or other option values. `OBJECT+x` has other `-D` flags.
A fixup sets section names, constants and map definitions, and makes large hash maps small. It adds, removes or moves no insn of a
program. DWARF is removed, BTF and line info stay.

## Add a project

Put its tree into `src/NAME`, write `src/NAME/jobs`, add a line to `projects.tsv`, and delete the
files that `tools/prune.py NAME` does not print, but keep the licence files.

## Licences

The scripts are GPL-2.0-only OR BSD-2-Clause. Each file in `src/` and `include/` keeps the licence
of its project, see `projects.tsv`, `include/README` and `LICENSES/`. An object has the licence of
its sources. Objects that read kernel headers (`--x86-ir` in jobs) are GPL-2.0. Each `vmlinux*.h`
is generated from the BTF of a Linux kernel. The profiler of coolbpf has code of
opentelemetry-ebpf-profiler (GPL-2.0), and kubeshark-tracer has code of Tracee (Apache-2.0).
