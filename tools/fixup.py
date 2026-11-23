# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
"""Do in the object what the loader of a project does at load time.

After that plain 'veristat OBJECT' loads it. No insn of a program is added, removed or
moved. The fixups of an object are in the last field of its line in src/PROJECT/jobs:

  sec:GLOB=NEW          new name of the sections that match: type of program, attach target
  secprog:PROG=NEW      the same for one program
  set:VAR=VALUE         initial value of a global variable, as in veristat -G
  set:@FILE             the same for each line of a file
  keep:GLOB,..          only these programs stay
  drop:GLOB,..          these programs leave
  dropsec:GLOB          the programs of these sections leave
  core-old              CO-RE relocations for members of old kernels, see core.py
  core-local:GLOB,..    CO-RE relocations for types that the kernel does not have
  ksym:NAME=VALUE       address of a symbol that the kernel does not have
  license:STR           for an object that has no license
  hidden                global functions are verified as static functions
  const:@TABLE,NAME=VALUE,..
                        constants of ebpf-manager: 'r = NAME ll' gets the value or 0
  xadd                  with const: telemetry of Datadog is on

'ni,pl?hidden' is only for these flavours, '!nc?set:a=1' is for all others.
Files are relative to src/PROJECT. fixup() has the steps for all objects.
"""
import functools, re, struct
from array import array
from fnmatch import fnmatchcase
from elfbtf import *
import core

# section_defs[] of libbpf (LGPL-2.1 OR BSD-2-Clause). 'x+' is 'x' or 'x/..'.
# Programs in the sections of one line can share a prog array.
SECTIONS = """
socket
sk_reuseport/migrate
sk_reuseport
kprobe+ uprobe+ kretprobe+ uretprobe+ ksyscall+ kretsyscall+
uprobe.s+ uretprobe.s+
kprobe.multi+ kretprobe.multi+
kprobe.session+
uprobe.multi+ uretprobe.multi+ usdt+
uprobe.multi.s+ uretprobe.multi.s+ usdt.s+
uprobe.session+
uprobe.session.s+
tc/ingress tcx/ingress
tc/egress tcx/egress
tc classifier
tracepoint+ tp+
tracepoint.s+ tp.s+
raw_tracepoint+ raw_tp+
raw_tracepoint.s+ raw_tp.s+
raw_tracepoint.w+ raw_tp.w+
""".strip().splitlines() + """
action netkit/primary netkit/peer syscall perf_event sockops sk_msg sk_lookup netfilter
xdp.frags/devmap xdp/devmap xdp.frags/cpumap xdp/cpumap xdp.frags xdp
lwt_in lwt_out lwt_xmit lwt_seg6local lirc_mode2 flow_dissector
sk_skb/stream_parser sk_skb/stream_verdict sk_skb/verdict sk_skb
cgroup_skb/ingress cgroup_skb/egress cgroup/skb cgroup/sock_create cgroup/sock_release
cgroup/sock cgroup/post_bind4 cgroup/post_bind6 cgroup/bind4 cgroup/bind6
cgroup/connect4 cgroup/connect6 cgroup/connect_unix cgroup/sendmsg4 cgroup/sendmsg6
cgroup/sendmsg_unix cgroup/recvmsg4 cgroup/recvmsg6 cgroup/recvmsg_unix
cgroup/getpeername4 cgroup/getpeername6 cgroup/getpeername_unix
cgroup/getsockname4 cgroup/getsockname6 cgroup/getsockname_unix
cgroup/sysctl cgroup/getsockopt cgroup/setsockopt cgroup/dev
""".split()
# Here the attach target matters too.
WITH_TARGET = """
tp_btf+ tp_btf.s+ fentry+ fmod_ret+ fexit+ fentry.s+ fmod_ret.s+ fexit.s+
fsession+ fsession.s+ fsession.multi+ fsession.multi.s+ fentry.multi+ fexit.multi+
fentry.multi.s+ fexit.multi.s+ lsm+ lsm.s+ lsm_cgroup+ iter+ iter.s+
""".split()
# bpf_lsm_disabled_hooks of the kernel
DISABLED = """
vm_enough_memory inode_need_killpriv inode_getsecurity inode_listsecurity inode_copy_up_xattr
getselfattr getprocattr setprocattr key_getsecurity audit_rule_match xfrm_decode_session
ismaclabel file_alloc_security
""".split()
ALONE = ['freplace+', 'struct_ops+', 'struct_ops.s+']
KNOWN = {s: line for line in SECTIONS + WITH_TARGET + ALONE for s in line.split()}
BY_CTX = dict(x.split('=') for x in """
__sk_buff=tc sk_buff=tc bpf_sock=cgroup/post_bind4 bpf_sock_addr=cgroup/bind4
bpf_sock_ops=sockops sk_msg_md=sk_msg bpf_cgroup_dev_ctx=cgroup/dev bpf_sysctl=cgroup/sysctl
bpf_sockopt=cgroup/setsockopt sk_reuseport_md=sk_reuseport/migrate bpf_sk_lookup=sk_lookup
xdp_md=xdp bpf_user_pt_regs_t=kprobe pt_regs=kprobe bpf_perf_event_data=perf_event
bpf_raw_tracepoint_args=raw_tracepoint
""".split())

ARRAY, PROG_ARRAY, PERF_EVENT_ARRAY, STACK_TRACE, ARRAY_OF_MAPS, HASH_OF_MAPS = 2, 3, 4, 7, 12, 13
DEVMAP, CPUMAP, CGROUP_STORAGE, PERCPU_CGROUP_STORAGE, DEVMAP_HASH = 14, 16, 19, 21, 25
RINGBUF, USER_RINGBUF = 27, 31
LOCAL_STORAGE = 24, 28, 29, 32
# The verifier does not read the size of hash maps, stack maps and ring buffers.
# Small maps load fast and many loads can run at the same time.
MAX_ENTRIES = dict.fromkeys((1, 5, 7, 9, 10, 11, 13, 18), 1024) | dict.fromkeys((27, 31), 1 << 18)
MAP_FIELDS = ('type max_entries map_flags numa_node key_size key value_size value values '
              'map_extra').split()
DATA = ('.data', '.rodata', '.bss', '.percpu', '.maps', '.jumptables', '.addr_space.1',
        '.struct_ops')
ARENA = '.addr_space.1'
LIBCALL = re.compile(r'mem(set|cpy|move|cmp)|bcmp|str(len|n?cmp|n?cpy)|abort|__[a-z]+[sdt]i[23]')
CALL_MINUS_1 = b'\x85\x00\x00\x00\xff\xff\xff\xff'
MOV_R1_R1 = b'\xbf\x11\x00\x00\x00\x00\x00\x00'
XADD_R1_R2 = b'\xc3\x21\x00\x00\x00\x00\x00\x00'


def matches(name, globs):
    return any(fnmatchcase(name, g) for g in globs)


def read_lines(path):
    with open(path) as f:
        return [l for l in (l.split('#')[0].strip() for l in f) if l]


# ---- programs and sections

def sec_def(name):
    name = name.lstrip('?')
    return KNOWN.get(name) or KNOWN.get(name.split('/')[0] + '+')


def btf_func(o, f):
    return o.btf.types[f.ext[FUNC_INFO][1]] if f.ext[FUNC_INFO] else None


def guess_section(o, f):
    """The longest known prefix that no letter follows, else by the type of the argument."""
    name = f.sec.lstrip('?')
    for n in range(len(name) - 1, 0, -1):
        if not name[n].isalpha() and sec_def(name[:n]):
            return name[:n]
    func = btf_func(o, f)
    args = o.btf.types[func.type].m if func else ()
    ptr = o.btf.types[o.btf.skip(args[0][1]) if args else 0]
    t = o.btf.types[ptr.type if ptr.kind == K_PTR else 0]
    while t.kind in MODS and t.name not in BY_CTX:
        t = o.btf.types[t.type]
    return BY_CTX.get(t.name, f.sec)


def callees_to_text(o):
    """libbpf wants the functions that are called in .text."""
    copies = {}
    for f in o.funcs:           # the list grows
        for c in f.calls:
            if c[1].entry and c[1].sym.bind == LOCAL:
                c[1].sec = '.text'
            elif c[1].entry:
                if c[1] not in copies:
                    copies[c[1]] = g = c[1].copy()
                    g.sec = '.text'
                    o.funcs.append(g)
                c[1] = copies[c[1]]


def drop_progs(o, gone):
    o.funcs = [f for f in o.funcs if f not in gone]
    o.ptrs = [p for p in o.ptrs if p[2] not in gone]


def drop_libcalls(o):
    """The compiler may emit a call to memset(). One such program must not stop the others."""
    bad = {f for f in o.funcs if any(r.sym.sec is None and LIBCALL.fullmatch(r.sym.name)
                                     for r in f.rels)}
    gone = {f for f in o.progs() if bad and bad & reachable([f])}
    if len(gone) < len(o.progs()):
        drop_progs(o, gone)


def name_sections(o, by_sec, by_prog):
    for f in o.progs():
        new = by_prog.get(f.name) or next((n for g, n in by_sec if fnmatchcase(f.sec, g)), f.sec)
        f.sec = new
        if not sec_def(new):
            f.sec = guess_section(o, f)
        if f.sym.bind == LOCAL:
            f.sym.bind = GLOBAL
            if btf_func(o, f):
                btf_func(o, f).vlen = 1


def drop_disabled_hooks(o):
    drop_progs(o, {f for f in o.progs() if f.sec.startswith('lsm') and
                   f.sec.partition('/')[2] in DISABLED})


def reachable(roots):
    seen, todo = set(roots), list(roots)
    while todo:
        for _, to in todo.pop().calls:
            if to not in seen:
                seen.add(to)
                todo.append(to)
    return seen


def drop_unused_funcs(o):
    tags = {t.name.split(':')[1] for _, t in (o.btf.of_kind(K_DECL_TAG) if o.btf else ())
            if t.name.startswith('exception_callback:')}
    roots = [f for f in o.funcs if f.entry or f.name in tags] + [p[2] for p in o.ptrs]
    live = reachable(roots)
    o.funcs = [f for f in o.funcs if f in live]


def hide_funcs(o):
    for f in o.funcs:
        if not f.entry and f.sym.bind != LOCAL:
            f.sym.other = STV_HIDDEN


def fix_line_info(o):
    """The kernel wants a record for the first insn of each function and one record per
    insn. gcc does not always do that."""
    if not any(f.ext[LINE_INFO] for f in o.funcs):
        return
    for f in o.funcs:
        recs = f.ext[LINE_INFO]
        if not recs or recs[0]:
            recs[:0] = array('I', [0]) + (recs[1:4] or array('I', [0, 0, 0]))
        if len(set(recs[::4])) * 4 < len(recs):
            first = {recs[i]: i for i in range(len(recs) - 4, -1, -4)}
            f.ext[LINE_INFO] = array('I', [x for i in sorted(first.values())
                                           for x in recs[i:i + 4]])


# ---- constants

def bake_symbols(o, value):
    """value(function, name) is the number for 'r = name ll', or None."""
    for f in o.funcs:
        rels = []
        for r in f.rels:
            v = None
            if r.sym.sec is None and f.data[r.off] == LD_IMM64:
                v = value(f, r.sym.name)
            if v is None:
                rels.append(r)
            else:
                f.data[r.off + 1] &= 15
                set_imm64(f.data, r.off, v)
        f.rels = rels


def arg_count(sec):
    k = core.kernel()
    func = k.find(K_FUNC, sec.partition('/')[2])
    return len(k.types[k.types[func].type].m) if func else 0


def constants(o, args, xadd, project_dir):
    table = {}
    for a in args:
        lines = read_lines(project_dir + '/' + a[1:]) if a[0] == '@' else [a.replace('=', ' ')]
        table.update((l.split()[0], int(l.split()[1], 0)) for l in lines)
    externs = set(btf_externs(o))
    bake_symbols(o, lambda f, name: None if name in externs else
                 arg_count(f.sec) if name == 'fentry_func_argc' else table.get(name, 0))
    for f in o.funcs:
        for p in list(find_insns(f.data, CALL_MINUS_1)):
            f.data[p:p + 8] = XADD_R1_R2 if xadd else MOV_R1_R1


def number(btf, text, enum=None):
    if re.fullmatch(r'[+-]?0\d+', text):
        return int(text, 8)
    if re.fullmatch(r'[+-]?\d\w*', text):
        return int(text, 0)
    for t in [enum] if enum else [t for _, t in btf.of_kind(K_ENUM, K_ENUM64)]:
        for m in t.m:
            if m[0] == text:
                return m[1] | m[2] << 32 if t.kind == K_ENUM64 else m[1]
    raise Err('no enumerator ' + text)


def set_var(o, line):
    path, val = (x.strip() for x in line.split('='))
    name, *steps = re.findall(r'\w+|\[', path)
    btf = o.btf
    var = next((t for _, t in btf.of_kind(K_VAR) if t.name == name), None)
    sym = next((y for y in o.syms if y.name == name and y.type == OBJECT), None)
    if not var or not sym:
        raise Err('no variable ' + name)
    off, t = sym.value, btf.types[btf.skip(var.type)]
    while steps:
        step = steps.pop(0)
        if step == '[':
            i = number(btf, steps.pop(0))
            if t.kind != K_ARRAY or not 0 <= i < t.m[2]:
                raise Err('bad index in ' + path)
            ty, off = t.m[0], off + i * btf.size(t.m[0])
        else:
            m = t.kind in core.COMPOSITE and core.find_member(btf, t, step)
            if not m:
                raise Err('no member ' + path)
            ty, off = m[0], off + m[1] // 8
        t = btf.types[btf.skip(ty)]
    if t.kind not in (K_INT, K_ENUM, K_ENUM64):
        raise Err(path + ' is no integer')
    if sym.sec.type != SHT_NOBITS:      # the verifier knows no value in .bss
        v = number(btf, val, None if t.kind == K_INT else t)
        sym.sec.data[off:off + t.size] = (v % (1 << 8 * t.size)).to_bytes(t.size, 'little')


# ---- maps

class Maps:
    def __init__(self, o):
        self.o, self.btf, self.sec = o, o.btf, o.sec('.maps')
        self.datasec = self.btf.datasec('.maps')
        self.int = next((i for i, t in self.btf.of_kind(K_INT) if t.size == 4), 0) or \
            self.btf.add('int', K_INT, 4, [1 << 24 | 32])
        syms = {y.name: y for y in o.syms if y.sec is self.sec and y.type == OBJECT}
        self.var = {syms[self.btf.types[x[0]].name]: x[0] for x in self.datasec.m}

    def definition(self, sym):
        return self.btf.types[self.btf.skip(self.btf.types[self.var[sym]].type)]

    def get(self, d, name):
        """The number in '__uint(name, number)' or the size of '__type(name, type)'."""
        for n, ty, _ in d.m:
            to = self.btf.types[self.btf.skip(ty)].type
            if n == name and self.btf.types[to].kind != K_ARRAY:
                raise Err('bad map definition')
            if n == name:
                return self.btf.types[to].m[2]
            if n + '_size' == name:
                return self.btf.size(to)
        return 0

    def add(self, d, name, ty, size=8):
        d.m.append([name, ty, d.type * 8])
        d.type += size

    def set(self, d, name, val):
        if self.get(d, name) != val:
            d.m = [m for m in d.m if name not in (m[0], m[0] + '_size')]
            if val:
                arr = self.btf.add('', K_ARRAY, m=[self.int, self.int, val])
                self.add(d, name, self.btf.add('', K_PTR, arr))

    def fill(self, d, inner=False):
        """What other loaders fill in or ignore."""
        d.m = [m for m in d.m if m[0] in MAP_FIELDS]
        kind = self.get(d, 'type')
        values = next((m for m in d.m if m[0] == 'values'), None)
        if kind == PERF_EVENT_ARRAY:
            self.set(d, 'key_size', 4)
            self.set(d, 'value_size', 4)
        elif kind in (RINGBUF, USER_RINGBUF):
            self.set(d, 'key_size', 0)
            self.set(d, 'value_size', 0)
        elif kind == STACK_TRACE:
            self.set(d, 'key_size', 4)
            self.set(d, 'value_size', self.get(d, 'value_size') or 8)
        elif kind in (ARRAY_OF_MAPS, HASH_OF_MAPS) and values:
            ptr = self.btf.types[self.btf.skip(self.btf.types[values[1]].m[0])]
            self.fill(self.btf.types[self.btf.skip(ptr.type)], True)
        elif kind in (ARRAY_OF_MAPS, HASH_OF_MAPS):
            # User space makes the inner map. Without one libbpf loads no program at all.
            i = self.btf.add('', K_STRUCT, 0, [])
            for name, val in dict(type=ARRAY, key_size=4, value_size=8, max_entries=1).items():
                self.set(self.btf.types[i], name, val)
            self.set(d, 'value_size', 0)
            arr = self.btf.add('', K_ARRAY, m=[self.btf.add('', K_PTR, i), self.int, 0])
            self.add(d, 'values', arr, 0)
        if self.get(d, 'max_entries') > MAX_ENTRIES.get(kind, 1 << 32):
            arr = self.btf.add('', K_ARRAY, m=[self.int, self.int, MAX_ENTRIES[kind]])
            next(m for m in d.m if m[0] == 'max_entries')[1] = self.btf.add('', K_PTR, arr)
        if inner and kind not in LOCAL_STORAGE and not self.get(d, 'max_entries'):
            self.set(d, 'max_entries', 4096 if kind in (RINGBUF, USER_RINGBUF) else 1)

    def place(self, sym, size):
        sym.value, sym.size = len(self.sec.data), size
        self.sec.data += bytes(size)

    def make_global(self):
        """libbpf takes no static map."""
        at = {y.value: y for y in self.var}
        for f in self.o.funcs:
            for r in f.rels:
                if r.sym.sec is self.sec and r.sym.type == SECTION:
                    r.sym = at[get_imm(f.data, r.off)]
                    set_imm(f.data, r.off, 0)
        for r in self.sec.rels:
            if r.sym.type == SECTION:
                r.sym = at[struct.unpack_from('<Q', self.sec.data, r.off)[0]]
                struct.pack_into('<Q', self.sec.data, r.off, 0)
        for y, var in self.var.items():
            y.bind = y.bind or GLOBAL
            self.btf.types[var].m = [1]

    def inner_maps_first(self):
        """libbpf creates the maps in the order of .maps. gcc has them in reverse order."""
        for y in self.var:
            slots = [r for r in self.sec.rels if 0 <= r.off - y.value < y.size]
            if any(r.sym.value > y.value for r in slots):
                old = y.value
                self.place(y, y.size)
                for r in slots:
                    r.off += y.value - old

    def copy(self, sym, n):
        new = Sym('%s__%d' % (sym.name, n), GLOBAL, OBJECT, sec=self.sec)
        self.place(new, sym.size)
        self.o.syms.append(new)
        self.var[new] = self.btf.add(new.name, K_VAR, self.btf.types[self.var[sym]].type, [1])
        return new

    def split_by_class(self):
        """A map that holds programs takes the type of its first user and refuses other
        types, see bpf_prog_map_compatible(). veristat creates the maps once per object.
        Each class of programs gets its own copy of the map, and of the functions that use it."""
        kind = {y: self.get(self.definition(y), 'type') for y in self.var}
        owned = {y for y in kind if kind[y] in (PROG_ARRAY, DEVMAP, DEVMAP_HASH, CPUMAP)}
        storage = {y for y in kind if kind[y] in (CGROUP_STORAGE, PERCPU_CGROUP_STORAGE)}
        uses = lambda funcs, maps: frozenset(r.sym for f in funcs for r in f.rels if r.sym in maps)
        users = {f for f in self.o.funcs if uses([f], owned)}
        tainted = {f for f in self.o.funcs if users & reachable([f])} if users else set()
        cls = {}
        for f in self.o.progs():
            if f in tainted:
                d = sec_def(f.sec)
                d = f.sec if d in WITH_TARGET else f.name if d in ALONE else d
                cls[f] = d, uses(reachable([f]), storage)
        if len(set(cls.values())) < 2:
            return
        copies = {y: {} for y in owned}

        def rewrite(f, c):
            for r in f.rels:
                if r.sym in owned:
                    have = copies[r.sym]
                    if c not in have:
                        have[c] = self.copy(r.sym, len(have) + 1) if have else r.sym
                    r.sym = have[c]
            for call in f.calls:
                if call[1] in tainted:
                    if (call[1], c) not in copies:
                        copies[call[1], c] = g = call[1].copy()
                        self.o.funcs.append(g)
                        rewrite(g, c)
                    call[1] = copies[call[1], c]

        for f, c in cls.items():
            rewrite(f, c)
        drop_unused_funcs(self.o)

    def fix(self):
        self.make_global()
        for y in self.var:
            self.fill(self.definition(y))
        for y in self.var:
            if self.definition(y).size > y.size:
                self.place(y, self.definition(y).size)
        self.inner_maps_first()
        self.split_by_class()
        self.datasec.type = len(self.sec.data)
        self.datasec.m = sorted(([v, y.value, y.size] for y, v in self.var.items()),
                                key=lambda x: x[1])


# ---- externs and checks

def btf_externs(o):
    """name -> id of what libbpf resolves: kfuncs, __ksym and __kconfig."""
    return {o.btf.types[x[0]].name: x[0] for _, t in (o.btf.of_kind(K_DATASEC) if o.btf else ())
            if t.name in ('.ksyms', '.kconfig') for x in t.m}


def drop_unused_externs(o):
    used = {r.sym for r in o.rels() if r.sym.sec is None}
    o.syms = [y for y in o.syms if y.sec is not None or y in used]
    names, externs = {y.name for y in used}, btf_externs(o)
    if names - set(externs):
        raise Err('undefined symbol ' + ' '.join(sorted(names - set(externs))))
    if not o.btf:
        return
    live = {externs[n] for n in names}
    for i, t in o.btf.of_kind(K_DATASEC, K_VAR, K_FUNC):
        if t.kind == K_DATASEC and t.name in ('.ksyms', '.kconfig'):
            t.m = [x for x in t.m if x[0] in live]
            if not t.m:
                t.name, t.kind, t.type = '', K_STRUCT, 0
        elif t.kind == K_VAR and t.m == [2] and i not in live:
            t.type, t.m = o.btf.of_kind(K_INT)[0][0], [0]
        elif t.kind == K_FUNC and t.vlen == 2 and i not in live:
            t.vlen = 0
            for arg in o.btf.types[t.type].m:
                arg[0] = arg[0] or (arg[1] and 'arg' or '')


def check(o):
    if not o.progs():
        raise Err('no program')
    for f in o.funcs:
        for r in f.rels:
            sec = r.sym.sec
            if f.data[r.off] not in (LD_IMM64, CALL):
                raise Err('%s: relocation of insn 0x%x' % (f.name, f.data[r.off]))
            if sec is not None and not (isinstance(sec, Sec) and sec.name.startswith(DATA)):
                raise Err('%s: reference to %s in section %s' %
                          (f.name, r.sym.name, getattr(sec, 'name', sec)))


def parse(tokens, flavour):
    ops = {}
    for tok in tokens:
        m = re.match(r'(!?)([\w,]*)\?(.*)', tok)
        if m:
            if (flavour in m[2].split(',')) == bool(m[1]):
                continue
            tok = m[3]
        op, _, arg = tok.partition(':')
        if op not in ('sec secprog set keep drop dropsec core-old core-local ksym license '
                      'hidden const xadd').split():
            raise Err('unknown fixup ' + tok)
        many = op in ('keep', 'drop', 'core-local', 'const', 'ksym')
        ops.setdefault(op, []).extend(filter(None, arg.split(',')) if many else [arg])
    return ops


def robust(fn):
    @functools.wraps(fn)
    def wrapper(*args):
        try:
            return fn(*args)
        except (struct.error, LookupError, ValueError, AttributeError, TypeError, OSError) as e:
            raise Err('%s: %s' % (type(e).__name__, e))
    return wrapper


@robust
def fixup(raw_path, out_path, tokens, project_dir, flavour):
    ops = parse(tokens, flavour)
    get = lambda op: ops.get(op, [])
    if flavour == 'nc' and any(x[0] == '@' for x in get('set')):
        raise Err('skip')
    o = Obj(raw_path)
    if o.sec('maps'):
        raise Err("legacy section 'maps'")
    callees_to_text(o)
    drop_progs(o, {f for f in o.progs() if
                   matches(f.name, get('drop')) or matches(f.sec, get('dropsec')) or
                   not matches(f.name, get('keep') or ['*'])})
    name_sections(o, [x.rsplit('=', 1) for x in get('sec')],
                  dict(x.split('=', 1) for x in get('secprog')))
    drop_disabled_hooks(o)
    drop_libcalls(o)
    drop_unused_funcs(o)
    if 'hidden' in ops:
        hide_funcs(o)
    if 'license' in ops and not o.sec('license'):
        o.secs.append(Sec('license', flags=SHF_ALLOC | SHF_WRITE,
                          data=get('license')[0].encode() + b'\0'))
    if 'ksym' in ops:
        ksyms = {n: int(v, 0) for n, v in (x.split('=') for x in get('ksym'))}
        bake_symbols(o, lambda f, name: ksyms.get(name))
    if 'const' in ops:
        constants(o, get('const'), 'xadd' in ops, project_dir)
    for x in get('set'):
        for line in read_lines(project_dir + '/' + x[1:]) if x[0] == '@' else [x]:
            set_var(o, line)
    if 'core-old' in ops or 'core-local' in ops:
        core.bake(o, 'core-old' in ops, get('core-local'))
    if o.sec('.maps'):
        Maps(o).fix()
    drop_unused_externs(o)
    fix_line_info(o)
    check(o)
    o.write(out_path)


# ---- arena variables and the linker of libbpf. The build of scx does the same.

def has_arena(path):
    with open(path, 'rb') as f:
        return ARENA.encode() in f.read()


@robust
def before_link(path):
    """clang defines 'extern __arena' variables with size 0. Make them undefined."""
    if has_arena(path):
        e = Elf(path, needed)
        for y in e.syms:
            if y.sec is e.sec(ARENA) and y.sec and y.type == NOTYPE and not y.size:
                y.sec, y.value = None, 0
        e.write(path)


@robust
def after_link(path):
    """The offsets of the arena variables in BTF come from the symbol table."""
    if has_arena(path):
        e = Elf(path)
        sec, btf = e.sec('.BTF'), Btf(e.sec('.BTF').data)
        datasec, arena = btf.datasec(ARENA), e.sec(ARENA)
        if datasec and arena:
            at = {y.name: y.value for y in e.syms if y.sec is arena and y.type == OBJECT}
            for x in datasec.m:
                x[1] = at[btf.types[x[0]].name]
            datasec.m.sort(key=lambda x: x[1])
            names = {s: off for off, s in btf.names.items()}
            hlen, toff, tlen = struct.unpack_from('<III', sec.data, 4)
            sec.data[hlen + toff:hlen + toff + tlen] = btf.raw_types(names)
            e.write(path)


if __name__ == '__main__':
    import sys
    fixup(sys.argv[1], sys.argv[2], sys.argv[3:], '.', '')
