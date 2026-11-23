#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
"""build.py [-t TARGETS] [-c NAME=PATH].. [-o DIR] [-j N] [-n] [PROJECT[/OBJECT]..]

Compile src/ into DIR/PROJECT/TARGET/PROJECT.OBJECT.TARGET.bpf.o

  PROJECT[/OBJECT]  globs, the default is all
  -t TARGETS        globs of COMPILER-CPU[-FLAVOUR], separated by commas.
                    The default is what the file 'matrix' says.
  -c NAME=PATH      one more compiler. NAME starts with clang or gcc.
  -o DIR            the default is obj
  -n                print the commands, run nothing

  ./build.py                                 all that the archives in obj/ have
  ./build.py -t 'clang-20-v?' tetragon       clang 20 with -mcpu=v2, v3 and v4
  ./build.py -t '*-v3,*-v3-O1' 'bcc/tcp*'    each compiler, -O2 and -O1
  ./build.py -c clang-git=/llvm/bin/clang -t 'clang-git-v4'

The compilers are cc/clang-N and cc/gcc-N (see get-cc.sh), else clang-N and
bpf-gcc in $PATH. No header of the host is read. An object that is linked
from many files needs bpftool ($BPFTOOL or $PATH).
"""
import argparse, fnmatch, glob, multiprocessing, os, re, shlex, shutil, subprocess, sys, tempfile

TOP = os.path.dirname(os.path.realpath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, TOP + '/tools')
import fixup

CPUS = ['v2', 'v3', 'v4']
FLAVOURS = {
    '': [],
    'O1': ['-O1'], 'Os': ['-Os'], 'O3': ['-O3'],
    # always_inline is dropped: the compiler decides
    'pl': ['-Dalways_inline=__unused__', '-D__always_inline__=__unused__'],
    # always_inline becomes noinline: static subprogs
    'ni': ['-Dalways_inline=__noinline__', '-D__always_inline__=__noinline__'],
    # the verifier does not know the value of a 'const volatile' option
    'nc': ['-Dconst='],
}
INC = '../../include'       # the compilers run in src/PROJECT
KERNEL = [x for d in ('arch/x86/include', 'arch/x86/include/generated', 'include',
                      'arch/x86/include/uapi', 'arch/x86/include/generated/uapi',
                      'include/uapi', 'include/generated/uapi')
          for x in ('-isystem', INC + '/kernel/' + d)] + \
         [x for h in ('compiler-version.h', 'kconfig.h')
          for x in ('-include', INC + '/kernel/include/linux/' + h)]
NO_ERROR = ['int-conversion', 'implicit-function-declaration', 'implicit-int',
            'incompatible-pointer-types', 'incompatible-function-pointer-types']
BPFTOOL = os.environ.get('BPFTOOL') or shutil.which('bpftool')
TIMEOUT = 1800


class Failed(Exception):
    pass


def run(cmd, cwd=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors='replace',
                           timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise Failed('timeout')
    if p.returncode:
        lines = p.stderr.splitlines() or ['exit code %d' % p.returncode]
        raise Failed(next((l for l in lines if re.search('error|Error|Segmentation', l)), lines[-1]))
    return p.stdout


class Compiler:
    def __init__(self, name, path):
        self.name, self.path, self.gcc = name, path, name.startswith('gcc')
        inc = run([path, '-print-file-name=include']).strip()
        self.front = ['-g', '-O2', '-w', '-nostdinc', '-isystem', inc]
        if self.gcc:
            self.target = []
            self.front += ['-gbtf', '-std=gnu17', '-fpermissive', '-include', INC + '/gcc-compat.h']
            self.back = ['-mco-re', '-masm=pseudoc', '-mframe-limit=4096']
            self.back += ['-gprune-btf'] if self.accepts('-gbtf', '-gprune-btf') else []
        else:
            self.target = ['-target', 'bpf']
            self.front += ['-fno-crash-diagnostics'] + ['-Wno-error=' + w for w in NO_ERROR]
            # One program with a big frame or memset() must not stop the whole file.
            self.back = [x for o in ('-bpf-stack-size=4096', '-bpf-max-stores-per-memfunc=256')
                         if self.accepts('-mllvm', o) for x in ('-mllvm', o)]
        self.cpus = [c for c in CPUS if self.accepts('-mcpu=' + c)]

    def accepts(self, *flags):
        p = subprocess.run([self.path] + self.target + list(flags) +
                           ['-c', '-x', 'c', '-o', '/dev/null', '-'],
                           input='int f(void) { return 0; }', text=True, capture_output=True)
        return p.returncode == 0 and not p.stderr

    def flags(self, job, flavour):
        # 'gcc?-DX' is only for gcc, 'clang-2[2-9]?-DX' only for these versions
        only = [re.fullmatch(r'(?:((?:clang|gcc)[^?]*)\?)?(.*)', x) for x in job.flags]
        f = [m[2] for m in only if matches(self.name, [(m[1] or '') + '*']) and m[2] != '--x86-ir']
        if '--x86-ir' in job.flags:
            f += KERNEL
        if self.gcc:
            f = [x for x in f if not x.startswith('-fdebug-default-version')]
        return (self.front + ['-ffile-prefix-map=%s=.' % job.dir] + f + FLAVOURS[flavour] +
                ['-idirafter', INC + '/libc'])

    def commands(self, job, src, cpus, flavour, tmp):
        """Returns the commands for all CPUs, and {cpu: (commands, object)}."""
        f = self.flags(job, flavour)
        out = {cpu: '%s.%s.o' % (tmp, cpu) for cpu in cpus}
        if '--x86-ir' in job.flags:
            # Kernel headers have x86 asm. The projects make x86 IR and give it to the BPF backend.
            opt = [x for x in f if x.startswith('-O')][-1:]
            return ([[self.path, '-target', 'x86_64-linux-gnu'] + f +
                     ['-S', '-emit-llvm', src, '-o', tmp + '.ll']],
                    {cpu: ([[self.path] + self.target + self.back + opt +
                            ['-mcpu=' + cpu, '-w', '-Xclang', '-disable-llvm-passes',
                             '-c', tmp + '.ll', '-o', out[cpu]]], out[cpu]) for cpu in cpus})
        base = {cpu: [self.path] + self.target + self.back + ['-mcpu=' + cpu] + f for cpu in cpus}
        if self.gcc:
            # gcc does not know '#pragma clang attribute': see tools/gcc_pragma.py
            return [], {cpu: ([base[cpu] + ['-E', src, '-o', out[cpu] + '.i'],
                               [sys.executable, TOP + '/tools/gcc_pragma.py', out[cpu] + '.i'],
                               base[cpu] + ['-c', out[cpu] + '.i', '-o', out[cpu]]], out[cpu])
                        for cpu in cpus}
        return [], {cpu: ([base[cpu] + ['-c', src, '-o', out[cpu]]], out[cpu]) for cpu in cpus}


def find_compilers(more):
    paths = {}
    for d in os.environ['PATH'].split(':'):
        for p in glob.glob(d + '/clang-[0-9][0-9]'):
            paths.setdefault(os.path.basename(p), p)
    for n in ('bpf-gcc', 'bpf-unknown-none-gcc'):
        if shutil.which(n):
            paths['gcc-' + run([n, '-dumpversion']).strip().split('.')[0]] = shutil.which(n)
    for p in glob.glob(TOP + '/cc/clang-*/bin/clang') + glob.glob(TOP + '/cc/gcc-*/bin/bpf-*-gcc'):
        paths[p.split('/')[-3]] = p
    paths.update(m.split('=', 1) for m in more)
    return [Compiler(n, os.path.abspath(p)) for n, p in sorted(paths.items())]


class Job:
    """The lines of src/PROJECT/jobs that have the same sources and flags."""
    def __init__(self, project, sources, flags):
        self.project, self.dir, self.flags = project, TOP + '/src/' + project, flags
        self.sources = [s for g in sources
                        for s in sorted(glob.glob(g, root_dir=self.dir, recursive=True)) or [g]]
        self.objects = []       # (name, fixups)


def read_jobs(project):
    """NAME = text                            a variable, $NAME in later lines
       OBJECT: SOURCES | FLAGS | FIXUPS       many sources are linked"""
    var, jobs = {}, {}
    text = open('%s/src/%s/jobs' % (TOP, project)).read().replace('\\\n', ' ')
    for line in text.splitlines():
        line = re.sub(r'\$(\w+)', lambda m: var[m[1]], line).strip()
        if not line or line[0] == '#':
            continue
        m = re.match(r'(\w+) = ?(.*)', line)
        if m:
            var[m[1]] = m[2]
            continue
        name, rest = line.split(':', 1)
        sources, flags, fixups = (shlex.split(x) for x in (rest.split(' | ') + ['', ''])[:3])
        job = jobs.setdefault((tuple(sources), tuple(flags)), Job(project, sources, flags))
        job.objects.append((name, fixups))
    return list(jobs.values())


def read_matrix():
    return [(l.split()[0], l.split()[1:]) for l in open(TOP + '/matrix').read()
            .replace('\\\n', ' ').splitlines() if l.strip() and l[0] != '#']


def matches(name, globs):
    return any(fnmatch.fnmatchcase(name, g) for g in globs)


def plan(patterns, compilers, targets):
    """A unit is (job, compiler, flavour, {cpu: [(name, fixups)]})."""
    patterns = [p if '/' in p else p + '/*' for p in patterns or ['*']]
    matrix = [('*', targets)] if targets else read_matrix()
    units = []
    for f in sorted(glob.glob(TOP + '/src/*/jobs')):
        project = f.split('/')[-2]
        if not matches(project, [p.split('/')[0] for p in patterns]):
            continue
        for job in read_jobs(project):
            want = []
            for name, fixups in job.objects:
                full = project + '/' + name
                if matches(full, patterns):
                    want.append((name, fixups, next(t for g, t in matrix if matches(full, [g]))))
            x86 = '--x86-ir' in job.flags
            for cc in compilers:
                for flavour in FLAVOURS if not (x86 and cc.gcc) else []:
                    todo = {}
                    for cpu in cc.cpus:
                        t = target(cc, cpu, flavour)
                        objs = [(n, fx) for n, fx, globs in want if matches(t, globs)]
                        if objs:
                            todo[cpu] = objs
                    for part in [todo] if x86 else [{c: o} for c, o in todo.items()]:
                        if part:
                            units.append((job, cc, flavour, part))
    return units


def target(cc, cpu, flavour):
    return '-'.join(filter(None, [cc.name, cpu, flavour]))


def build(unit):
    """Returns [(path of the object, None or why it failed)]."""
    job, cc, flavour, todo = unit
    res = []
    with tempfile.TemporaryDirectory(prefix='bpf-corpus.') as tmp:
        steps = [cc.commands(job, s, todo, flavour, '%s/%d' % (tmp, i))
                 for i, s in enumerate(job.sources)]
        for cpu, objects in todo.items():
            t = target(cc, cpu, flavour)
            paths = ['%s/%s/%s.%s.%s.bpf.o' % (job.project, t, job.project, n, t) for n, _ in objects]
            try:
                for common, per_cpu in steps:
                    for cmd in common + per_cpu[cpu][0]:
                        print(shlex.join(cmd)) if ARGS.n else run(cmd, job.dir)
                    common.clear()
                if ARGS.n:
                    continue
                raw = link([per_cpu[cpu][1] for _, per_cpu in steps], tmp + '/linked.o')
            except (Failed, fixup.Err) as e:
                res += [(p, str(e)) for p in paths]
                continue
            for p, (_, fixups) in zip(paths, objects):
                out = os.path.join(ARGS.o, p)
                try:
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    fixup.fixup(raw, out, fixups, job.dir, flavour)
                    res.append((p, None))
                except fixup.Err as e:
                    res.append((p, 'fixup: %s' % e))
    return [(p, e and e.replace(tmp, '').replace(TOP + '/', '')) for p, e in res]


def link(parts, out):
    if len(parts) == 1:
        return parts[0]
    if not BPFTOOL:
        raise Failed('no bpftool to link the object')
    for p in parts:
        fixup.before_link(p)
    run([BPFTOOL, 'gen', 'object', out] + parts)
    fixup.after_link(out)
    return out


def main():
    global ARGS
    ap = argparse.ArgumentParser(usage=__doc__)
    ap.add_argument('-t', default='')
    ap.add_argument('-c', action='append', default=[])
    ap.add_argument('-o', default=TOP + '/obj')
    ap.add_argument('-j', type=int, default=os.cpu_count())
    ap.add_argument('-n', action='store_true')
    ap.add_argument('patterns', nargs='*')
    ARGS = ap.parse_args()
    compilers = find_compilers(ARGS.c)
    print('compilers:', *[c.name for c in compilers], file=sys.stderr)
    units = plan(ARGS.patterns, compilers, [t for t in ARGS.t.split(',') if t])
    units.sort(key=lambda u: (-len(u[0].sources), '--x86-ir' not in u[0].flags))
    if ARGS.n:
        for u in units:
            build(u)
        return
    os.makedirs(ARGS.o, exist_ok=True)
    ok = failed = 0
    with multiprocessing.get_context('fork').Pool(ARGS.j) as pool, \
            open(ARGS.o + '/FAILED.tsv', 'a') as log:
        for n, res in enumerate(pool.imap_unordered(build, units), 1):
            for path, err in res:
                ok += not err
                failed += bool(err)
                if err:
                    if os.path.exists(os.path.join(ARGS.o, path)):
                        os.unlink(os.path.join(ARGS.o, path))
                    print(path, err[:300], sep='\t', file=log, flush=True)
            if sys.stderr.isatty():
                print('\r%d/%d' % (n, len(units)), end='', file=sys.stderr)
    print('\n%d objects, %d failed: %s/FAILED.tsv' % (ok, failed, ARGS.o), file=sys.stderr)


if __name__ == '__main__':
    main()
