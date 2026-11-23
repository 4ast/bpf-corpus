# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
"""Resolve at build time the CO-RE relocations that fail on a new kernel.

An old release of a project reads members that the kernel does not have any more,
like inode->i_ctime. libbpf poisons such an insn and the program does not load.
Each record is resolved against the BTF of the reference kernel, as in relo_core.c.
  It resolves:                        the record stays.
  It resolves with the old members:   the value goes into the insn, the record leaves.
  It matches a glob of core-local:    the record leaves, the insn keeps the local value.
  Else:                               the record stays.
"""
import copy, fnmatch, functools, lzma, os, struct
from array import array
from elfbtf import *

TOOLS = os.path.dirname(os.path.realpath(__file__))
(F_OFF, F_SIZE, F_EXISTS, F_SIGNED, F_LSHIFT, F_RSHIFT, T_ID_LOCAL, T_ID_TARGET, T_EXISTS,
 T_SIZE, E_EXISTS, E_VALUE, T_MATCHES) = range(13)
COMPOSITE, ENUMS = (K_STRUCT, K_UNION), (K_ENUM, K_ENUM64)


class Skip(Exception):
    """The record is left to libbpf."""


class NoMatch(Exception):
    pass


def essential(name):
    """'x___flavour' is 'x'."""
    for i in range(len(name) - 5, -1, -1):
        if name[i] != '_' and name[i + 1:i + 4] == '___' and name[i + 4] != '_':
            return name[:i + 1]
    return name


class Kernel(Btf):
    def __init__(self, raw):
        super().__init__(raw)
        self.by_name = {}
        for i, t in enumerate(self.types):
            if t.name:
                name = essential(t.name) if '___' in t.name else t.name
                self.by_name.setdefault(name, []).append(i)

    def candidates(self, name, kind):
        return [i for i in self.by_name.get(essential(name), ())
                if same_kind(self.types[i].kind, kind)]

    def find(self, kind, name):
        return next((i for i in self.candidates(name, kind) if self.types[i].name == name), 0)

    def member(self, i, name):
        """(type, bit offset). Members without a name are searched."""
        return find_member(self, self.types[i], name)


def find_member(btf, t, name):
    for k, (n, ty, _) in enumerate(t.m):
        if n == name:
            return ty, t.bit_offset(k)
        inner = btf.types[btf.skip(ty)]
        if not n and inner.kind in COMPOSITE:
            m = find_member(btf, inner, name)
            if m:
                return m[0], m[1] + t.bit_offset(k)


@functools.cache
def kernel():
    with lzma.open(TOOLS + '/../include/vmlinux.btf.xz') as f:
        return Kernel(f.read())


@functools.cache
def old_kernel():
    """The kernel with the members of core-old-members.txt."""
    b = copy.copy(kernel())
    b.types, b.by_name = list(b.types), dict(b.by_name)

    def parse(x):
        x = x.strip()
        if x.endswith('*'):
            return b.add('', K_PTR, 0 if x[:-1].strip() == 'void' else parse(x[:-1]))
        if x.endswith(']'):
            elem, n = x[:-1].split('[')
            return b.add('', K_ARRAY, m=[parse(elem), parse('unsigned int'), int(n)])
        if x.startswith('struct '):
            return b.find(K_STRUCT, x[7:])
        return b.find(K_TYPEDEF, x) or b.find(K_INT, x)

    for line in open(TOOLS + '/core-old-members.txt'):
        line = line.split('#')[0].strip()
        if '{' in line:
            head, body = line.rstrip('}').split('{')
            _, name, size = head.split()
            m = [x.rsplit(None, 1) for x in body.split(';') if x.strip()]
            m = [[x.split('@')[0], parse(ty), int(x.split('@')[1]) * 8] for ty, x in m]
            if not b.find(K_STRUCT, name):
                b.by_name[name] = [b.add(name, K_STRUCT, int(size), m)]
        elif line:
            new, old = line.split('=')
            (name, new), old = new.strip().split('.'), old.split(None, 1)
            i = b.find(K_STRUCT, name) or b.skip(b.find(K_TYPEDEF, name))
            m = b.member(i, old[0])
            if m and not b.member(i, new):
                t = b.types[i] = copy.copy(b.types[i])
                t.m = t.m + [[new, parse(old[1]) if len(old) > 1 else m[0], m[1]]]
    return b


def same_kind(a, b):
    return a == b or a in ENUMS and b in ENUMS


class Spec:
    """acc: (type id, index, name or None) for each step."""
    def __init__(self, btf, root, kind):
        self.btf, self.root, self.kind, self.acc, self.bit = btf, root, kind, [], 0

    def path(self):
        p = self.btf.types[self.root].name
        for k, (_, idx, name) in enumerate(self.acc):
            p += '.' + name if name else '[%d]' % idx if k else ''
        return p


def in_array(btf, acc, arr, idx):
    flex = acc[2] and not arr.m[2] and acc[1] == len(btf.types[acc[0]].m) - 1
    return flex or idx < arr.m[2]


def parse_spec(btf, tid, text, kind):
    sp = Spec(btf, tid, kind)
    if kind in (T_ID_TARGET, T_EXISTS, T_SIZE):
        return sp
    if kind in (T_ID_LOCAL, T_MATCHES):
        raise Skip
    raw = [int(x) for x in text.split(':')]
    i = btf.skip(tid)
    if kind in (E_EXISTS, E_VALUE):
        sp.acc.append((i, raw[0], btf.types[i].m[raw[0]][0]))
        return sp
    sp.acc.append((i, raw[0], None))
    sp.bit = raw[0] * btf.size(i) * 8
    for a in raw[1:]:
        i = btf.skip(i)
        t = btf.types[i]
        if t.kind in COMPOSITE:
            sp.bit += t.bit_offset(a)
            if t.m[a][0]:
                sp.acc.append((i, a, t.m[a][0]))
            i = t.m[a][1]
        elif t.kind == K_ARRAY and in_array(btf, sp.acc[-1], t, a):
            i = btf.skip(t.m[0])
            sp.acc.append((i, a, None))
            sp.bit += a * btf.size(i) * 8
        else:
            raise Skip
    return sp


def plain_ints(a, b):
    return not (a.m[0] | b.m[0]) >> 16 & 0xff


def fields_compat(lb, l, tb, t):
    a, b = lb.types[lb.skip(l)], tb.types[tb.skip(t)]
    if a.kind in COMPOSITE and b.kind in COMPOSITE:
        return True
    if not same_kind(a.kind, b.kind):
        return False
    if a.kind in (K_FWD,) + ENUMS:
        return not a.name or not b.name or essential(a.name) == essential(b.name)
    if a.kind == K_INT:
        return plain_ints(a, b)
    if a.kind == K_ARRAY:
        return fields_compat(lb, a.m[0], tb, b.m[0])
    return a.kind in (K_PTR, K_FLOAT)


def types_compat(lb, l, tb, t):
    a, b = lb.types[lb.skip(l)], tb.types[tb.skip(t)]
    if not same_kind(a.kind, b.kind):
        return False
    if a.kind == K_INT:
        return plain_ints(a, b)
    if a.kind == K_PTR:
        return types_compat(lb, a.type, tb, b.type)
    if a.kind == K_ARRAY:
        return types_compat(lb, a.m[0], tb, b.m[0])
    if a.kind == K_PROTO:
        return (len(a.m) == len(b.m) and types_compat(lb, a.type, tb, b.type) and
                all(types_compat(lb, x[1], tb, y[1]) for x, y in zip(a.m, b.m)))
    return a.kind in (0, K_FWD) + COMPOSITE + ENUMS


def match_member(lb, acc, tb, tid, sp):
    tid = tb.skip(tid)
    t = tb.types[tid]
    if t.kind not in COMPOSITE:
        return None
    for i, (name, ty, _) in enumerate(t.m):
        sp.bit += t.bit_offset(i)
        if not name:
            found = match_member(lb, acc, tb, ty, sp)
            if found is not None:
                return found
        elif name == acc[2]:
            if not fields_compat(lb, lb.types[acc[0]].m[acc[1]][1], tb, ty):
                raise NoMatch
            sp.acc.append((tid, i, name))
            return ty
        sp.bit -= t.bit_offset(i)
    return None


def match_spec(ls, tb, tid):
    sp = Spec(tb, tid, ls.kind)
    if not ls.acc:
        return sp if types_compat(ls.btf, ls.root, tb, tid) else None
    if ls.kind in (E_EXISTS, E_VALUE):
        tid = tb.skip(tid)
        for i, m in enumerate(tb.types[tid].m if tb.types[tid].kind in ENUMS else ()):
            if essential(m[0]) == essential(ls.acc[0][2]):
                sp.acc.append((tid, i, m[0]))
                return sp
        return None
    for k, a in enumerate(ls.acc):
        tid = tb.skip(tid)
        if a[2]:
            tid = match_member(ls.btf, a, tb, tid, sp)
            if tid is None:
                return None
            continue
        if k:
            t = tb.types[tid]
            if t.kind != K_ARRAY or not in_array(tb, sp.acc[-1], t, a[1]):
                return None
            tid = tb.skip(t.m[0])
        sp.acc.append((tid, a[1], None))
        sp.bit += a[1] * tb.size(tid) * 8
    return sp


def resolve(ls, tb):
    t = ls.btf.types[ls.root]
    for c in tb.candidates(t.name, t.kind):
        try:
            sp = match_spec(ls, tb, c)
        except NoMatch:
            continue
        if sp:
            return sp


def value(sp):
    """(value, id of the type that a load or store at this offset sees)"""
    b, kind = sp.btf, sp.kind
    if kind in (F_EXISTS, T_EXISTS, E_EXISTS):
        return 1, 0
    if kind == T_SIZE:
        return b.size(sp.root), 0
    if kind > F_RSHIFT:
        raise Skip
    tid, idx, name = sp.acc[-1]
    bits = b.types[tid].bit_size(idx) if name else 0
    if name:
        tid = b.skip(b.types[tid].m[idx][1])
    t, size, off = b.types[tid], b.size(tid), sp.bit // 8
    if bits:
        off = off // size * size
        while sp.bit + bits - off * 8 > size * 8:
            size *= 2
            off = sp.bit // 8 // size * size
    if kind == F_OFF:
        return off, 0 if bits else tid
    if kind == F_SIGNED:
        return int(t.kflag if t.kind in ENUMS else t.kind == K_INT and t.m[0] >> 24 & 1), 0
    bits = bits or size * 8
    return {F_SIZE: size, F_LSHIFT: 64 - (sp.bit + bits - off * 8), F_RSHIFT: 64 - bits}[kind], 0


def patch(d, off, ls, ts):
    (_, lt), (val, tt) = value(ls), value(ts)
    cls = d[off] & 7
    if d[off] == LD_IMM64:
        set_imm64(d, off, val)
    elif cls in (4, 7) and not d[off] & 8:          # ALU with an immediate
        set_imm(d, off, val)
    elif cls in (1, 2, 3) and val < 32768:          # LDX, ST, STX
        old, new = lt and ls.btf.size(lt), tt and ts.btf.size(tt)
        if old != new:
            a, b = ls.btf.types[lt], ts.btf.types[tt]
            if a.kind != K_INT or b.kind != K_INT or (a.m[0] | b.m[0]) >> 24 & 1 or new > 8:
                raise Skip
            d[off] = d[off] & 0xe7 | {4: 0, 2: 8, 1: 0x10, 8: 0x18}[new]
        struct.pack_into('<h', d, off + 2, val)
    else:
        raise Skip


def bake(obj, old, globs):
    """old: use the table of old members. globs: TYPE or TYPE.MEMBER.."""
    @functools.cache
    def plan(tid, text, kind):
        try:
            ls = parse_spec(obj.btf, tid, obj.btf.str(text), kind)
            if resolve(ls, kernel()):
                return None
            ts = old and resolve(ls, old_kernel())
            names = ls.path(), obj.btf.types[tid].name
            if ts or any(fnmatch.fnmatchcase(n, g) for n in names for g in globs):
                return ls, ts
        except (Skip, Err):
            pass

    for f in obj.funcs:
        recs, keep = f.ext[CORE_RELO], array('I')
        for i in range(0, len(recs), 4):
            todo = plan(*recs[i + 1:i + 4])
            try:
                if todo and todo[1]:
                    patch(f.data, recs[i], *todo)
            except Skip:
                todo = None
            if not todo:
                keep.extend(recs[i:i + 4])
        f.ext[CORE_RELO] = keep
