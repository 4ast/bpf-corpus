# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
"""Read and write a BPF object: ELF64 little endian, .BTF and .BTF.ext.

Elf(path) is the plain file: sections, symbols, relocations.
Obj(path) also cuts the code into functions. A function has its insns, its
relocations, its records of .BTF.ext and the name of its section. It can be
dropped, copied or moved to another section. write() lays the code out again.
"""
import re, os, struct
from array import array
from bisect import bisect_left, bisect_right

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOBITS, SHT_REL = 1, 2, 3, 4, 8, 9
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, SHF_INFO_LINK = 1, 2, 4, 0x40
LOCAL, GLOBAL, WEAK = 0, 1, 2
NOTYPE, OBJECT, FUNC, SECTION, FILE = 0, 1, 2, 3, 4
STV_HIDDEN = 2
R_LD64, R_ABS64, R_CALL = 1, 2, 10
LD_IMM64, CALL = 0x18, 0x85
PSEUDO_CALL = b'\x85\x10\x00\x00'

(K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM, K_FWD, K_TYPEDEF, K_VOLATILE, K_CONST,
 K_RESTRICT, K_FUNC, K_PROTO, K_VAR, K_DATASEC, K_FLOAT, K_DECL_TAG, K_TYPE_TAG,
 K_ENUM64) = range(1, 20)
MODS = (K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT, K_TYPE_TAG)
ONE = {K_INT: 1, K_ARRAY: 3, K_VAR: 1, K_DECL_TAG: 1}       # words behind the type
MANY = {K_STRUCT: 3, K_UNION: 3, K_ENUM: 2, K_PROTO: 2, K_DATASEC: 3, K_ENUM64: 3}
FUNC_INFO, LINE_INFO, CORE_RELO = range(3)
EXT_WORDS = (2, 4, 4)


class Err(Exception):
    pass


def cstr(b, off):
    return b[off:b.index(b'\0', off)].decode('latin-1')


def find_insns(data, head):
    """Offsets of the insns that start with these bytes."""
    p = data.find(head)
    while p >= 0:
        if p % 8 == 0:
            yield p
        p = data.find(head, p + 1)


def get_imm(data, off):
    return struct.unpack_from('<i', data, off + 4)[0]


def set_imm(data, off, val):
    struct.pack_into('<I', data, off + 4, val & 0xffffffff)


def set_imm64(data, off, val):
    set_imm(data, off, val)
    set_imm(data, off + 8, val >> 32)


class Strings(dict):
    """A string table that is being written: name -> offset."""
    def __init__(self):
        self.data = bytearray(1)
        self[''] = 0

    def __missing__(self, s):
        off = self[s] = len(self.data)
        self.data += s.encode('latin-1') + b'\0'
        return off


class Type:
    """'type' is also the size. m: the words behind the type, or a list of members.
    int [encoding], array [element, index, count], var [linkage], decl_tag [index],
    struct [name, type, offset], enum [name, value], enum64 [name, low, high],
    func_proto [name, type], datasec [type, offset, size]. vlen of a func is its linkage."""
    __slots__ = ('name', 'kind', 'kflag', 'vlen', 'type', 'm')

    def __init__(self, name, kind, type=0, m=(), kflag=0, vlen=0):
        self.name, self.kind, self.type, self.m = name, kind, type, m
        self.kflag, self.vlen = kflag, vlen

    @property
    def size(self):
        return self.type

    def bit_offset(self, i):
        return self.m[i][2] & 0xffffff if self.kflag else self.m[i][2]

    def bit_size(self, i):
        return self.m[i][2] >> 24 if self.kflag else 0


class Btf:
    def __init__(self, raw):
        magic, _, _, hlen, toff, tlen, soff, slen = struct.unpack_from('<HBBIIIII', raw)
        if magic != 0xeb9f:
            raise Err('.BTF: bad magic')
        self.strs = bytes(raw[hlen + soff:hlen + soff + slen])
        self.names = {}
        self.types = [Type('', 0)]
        w = array('I', bytes(raw[hlen + toff:hlen + toff + tlen]))
        p, end, s = 0, len(w), self.str
        while p < end:
            name, info, size = w[p:p + 3]
            kind, vlen, m = info >> 24 & 31, info & 0xffff, ()
            p += 3
            if kind in ONE:
                m = list(w[p:p + ONE[kind]])
                p += ONE[kind]
            elif kind in MANY:
                n = MANY[kind]
                m = [list(w[q:q + n]) for q in range(p, p + n * vlen, n)]
                p += n * vlen
                if kind != K_DATASEC:
                    for x in m:
                        x[0] = s(x[0])
            elif not K_INT <= kind <= K_ENUM64:
                raise Err('.BTF: kind %d' % kind)
            self.types.append(Type(s(name), kind, size, m, info >> 31, vlen))

    def str(self, off):
        s = self.names.get(off)
        if s is None:
            s = self.names[off] = cstr(self.strs, off)
        return s

    def add(self, *args, **kw):
        self.types.append(Type(*args, **kw))
        return len(self.types) - 1

    def of_kind(self, *kinds):
        return [(i, t) for i, t in enumerate(self.types) if t.kind in kinds]

    def datasec(self, name):
        return next((t for _, t in self.of_kind(K_DATASEC) if t.name == name), None)

    def skip(self, i):
        """The id behind typedefs and modifiers."""
        while self.types[i].kind in MODS:
            i = self.types[i].type
        return i

    def size(self, i):
        n = 1
        while True:
            t = self.types[i]
            if t.kind == K_PTR:
                return n * 8
            if t.kind == K_ARRAY:
                n, i = n * t.m[2], t.m[0]
            elif t.kind in MODS or t.kind == K_VAR:
                i = t.type
            elif t.kind in (0, K_FWD, K_FUNC, K_PROTO):
                raise Err('.BTF: type %d has no size' % i)
            else:
                return n * t.type

    def raw_types(self, strs):
        w = array('I')
        for t in self.types[1:]:
            many = t.kind in MANY
            vlen = len(t.m) if many else t.vlen
            w.extend((strs[t.name], t.kflag << 31 | t.kind << 24 | vlen, t.type))
            if t.kind == K_DATASEC:
                for x in t.m:
                    w.extend(x)
            elif many:
                for x in t.m:
                    w.append(strs[x[0]])
                    w.extend(x[1:])
            else:
                w.extend(t.m)
        return w.tobytes()


def read_ext(raw, btf):
    """Three tables {section name: words of its records}, sorted by the offset of the insn."""
    magic, _, _, hlen = struct.unpack_from('<HBBI', raw)
    if magic != 0xeb9f:
        raise Err('.BTF.ext: bad magic')
    tables = [{}, {}, {}]
    for k in range(min((hlen - 8) // 8, 3)):
        off, size = struct.unpack_from('<II', raw, 8 + 8 * k)
        w = array('I', bytes(raw[hlen + off:hlen + off + size]))
        n, p = EXT_WORDS[k], 1
        if size and w[0] != 4 * n:
            raise Err('.BTF.ext: record size %d' % w[0])
        while p < len(w):
            name, end = btf.str(w[p]), p + 2 + w[p + 1] * n
            tables[k].setdefault(name, array('I')).extend(w[p + 2:end])
            p = end
        for name, recs in tables[k].items():
            offs = recs[::n].tolist()
            if offs != sorted(offs):
                order = sorted(range(len(offs)), key=offs.__getitem__)
                tables[k][name] = array('I', [x for i in order for x in recs[i * n:i * n + n]])
    return tables


class Sec:
    def __init__(self, name, type=SHT_PROGBITS, flags=0, align=1, entsize=0, data=b''):
        self.name, self.type, self.flags = name, type, flags
        self.align, self.entsize, self.data = align, entsize, bytearray(data)
        self.rels = []      # the relocations that apply to this section

    @property
    def code(self):
        return self.type == SHT_PROGBITS and self.flags & SHF_EXECINSTR


class Sym:
    """sec is a Sec, None (undefined) or a special index."""
    __slots__ = ('name', 'bind', 'type', 'other', 'sec', 'value', 'size')

    def __init__(self, name, bind, type, other=0, sec=None, value=0, size=0):
        self.name, self.bind, self.type, self.other = name, bind, type, other
        self.sec, self.value, self.size = sec, value, size


class Rel:
    __slots__ = ('off', 'sym', 'type')

    def __init__(self, off, sym, type):
        self.off, self.sym, self.type = off, sym, type


class Elf:
    """secs has no relocation, symbol and string tables: write() makes them.
    keep(name) says if a section is read, keep_rel(sec) if its relocations are."""
    def __init__(self, path, keep=lambda name: True, keep_rel=lambda sec: True):
        with open(path, 'rb') as f:
            raw = f.read()
        if raw[:6] != b'\x7fELF\x02\x01':
            raise Err('not a little endian ELF64 file')
        self.ehdr = raw[:64]
        shoff, = struct.unpack_from('<Q', raw, 0x28)
        shnum, shstrndx = struct.unpack_from('<HH', raw, 0x3c)
        hdrs = list(struct.iter_unpack('<IIQQQQIIQQ', raw[shoff:shoff + 64 * shnum]))
        body = lambda h: raw[h[4]:h[4] + h[5]]
        names = body(hdrs[shstrndx])
        secs = {}
        for i, h in enumerate(hdrs):
            name = cstr(names, h[0])
            if h[1] in (SHT_PROGBITS, SHT_NOBITS) and keep(name):
                data = bytes(h[5]) if h[1] == SHT_NOBITS else body(h)
                secs[i] = Sec(name, h[1], h[2], h[8], h[9], data)
        self.secs = list(secs.values())
        symtab = next((h for h in hdrs if h[1] == SHT_SYMTAB), None)
        if not symtab:
            raise Err('no symbol table')
        names, syms = body(hdrs[symtab[6]]), []
        for name, info, other, ndx, value, size in struct.iter_unpack('<IBBHQQ', body(symtab)):
            sec = secs.get(ndx, ndx or None)
            syms.append(Sym(cstr(names, name), info >> 4, info & 15, other, sec, value, size))
        self.syms = [y for y in syms[1:] if not (isinstance(y.sec, int) and y.sec < shnum)]
        for h in hdrs:
            sec = secs.get(h[7])
            if h[1] in (SHT_REL, SHT_RELA) and sec and keep_rel(sec):
                if h[1] == SHT_RELA:
                    raise Err('RELA relocations for ' + sec.name)
                sec.rels += [Rel(off, syms[info >> 32], info & 0xffffffff)
                             for off, info in struct.iter_unpack('<QQ', body(h))]

    def sec(self, name):
        return next((s for s in self.secs if s.name == name), None)

    def write(self, path):
        syms = ([Sym('', LOCAL, NOTYPE)] + [y for y in self.syms if y.bind == LOCAL] +
                [y for y in self.syms if y.bind != LOCAL])
        sym_ndx = {y: i for i, y in enumerate(syms)}
        order = [(s, rel) for s in self.secs for rel in (0, 1) if not rel or s.rels]
        sec_ndx = {s: i for i, (s, rel) in enumerate(order, 1) if not rel}
        symtab, strs = len(order) + 1, Strings()
        out, hdrs = bytearray(64), bytearray(64)

        def put(name, type, flags, data, link, info, align, entsize):
            out.extend(bytes(-len(out) % max(align, 1)))
            hdrs.extend(struct.pack('<IIQQQQIIQQ', strs[name], type, flags, 0, len(out),
                                    len(data), link, info, align, entsize))
            if type != SHT_NOBITS:
                out.extend(data)

        for s, rel in order:
            if rel:
                w = array('Q', [x for r in s.rels for x in (r.off, sym_ndx[r.sym] << 32 | r.type)])
                put('.rel' + s.name, SHT_REL, SHF_INFO_LINK, w.tobytes(), symtab, sec_ndx[s], 8, 16)
            else:
                put(s.name, s.type, s.flags, s.data, 0, 0, s.align, s.entsize)
        data = b''.join(struct.pack('<IBBHQQ', strs[y.name], y.bind << 4 | y.type, y.other,
                                    sec_ndx.get(y.sec, y.sec or 0), y.value, y.size) for y in syms)
        locals_ = sum(y.bind == LOCAL for y in syms)
        put('.symtab', SHT_SYMTAB, 0, data, symtab + 1, locals_, 8, 24)
        strs['.strtab']
        put('.strtab', SHT_STRTAB, 0, strs.data, 0, 0, 1, 0)
        out.extend(bytes(-len(out) % 8))
        out[:64] = self.ehdr
        struct.pack_into('<Q', out, 0x28, len(out))
        struct.pack_into('<HHH', out, 0x3a, 64, symtab + 2, symtab + 1)
        tmp = '%s.tmp%d' % (path, os.getpid())
        with open(tmp, 'wb') as f:
            f.write(out + hdrs)
        os.replace(tmp, path)


class Func:
    """Offsets in rels, calls and ext count from the start of the function.
    calls: [offset, Func] for each insn that calls a function or loads its address.
    start: where it was in its section. Jump tables count from the start of the section."""
    def __init__(self, sym, sec, data, start):
        self.sym, self.sec, self.data, self.start = sym, sec, data, start
        self.rels, self.calls, self.ext = [], [], [array('I') for _ in EXT_WORDS]

    @property
    def name(self):
        return self.sym.name

    @property
    def entry(self):
        return self.sec != '.text'

    def copy(self):
        y = self.sym
        f = Func(Sym(y.name, y.bind, FUNC, y.other), self.sec, self.data[:], self.start)
        f.rels = [Rel(r.off, r.sym, r.type) for r in self.rels]
        f.calls = [c[:] for c in self.calls]
        f.ext = [x[:] for x in self.ext]
        return f


def needed(name):
    return not (name.startswith(('.debug', '.note')) or name in ('.comment', '.eh_frame'))


def relocated_by_libbpf(sec):
    return sec.code or sec.name.lstrip('?').startswith(
        ('.maps', '.struct_ops', '.rodata', '.data.rel.ro', '.addr_space.1'))


class Obj(Elf):
    """funcs: all code. ptrs: [section, offset, Func] for each pointer to code in data.
    secs and syms have no code until write()."""
    def __init__(self, path):
        super().__init__(path, needed, relocated_by_libbpf)
        btf, ext = self.sec('.BTF'), self.sec('.BTF.ext')
        self.btf = Btf(btf.data) if btf else None
        tables = read_ext(ext.data, self.btf) if btf and ext else [{}, {}, {}]
        code = {s: [] for s in self.secs if s.code}
        for y in self.syms:
            if y.type == FUNC and y.sec in code:
                if not y.size or y.size % 8 or y.value % 8 or y.value + y.size > len(y.sec.data):
                    raise Err('function %s has a bad size' % y.name)
                data = y.sec.data[y.value:y.value + y.size]
                code[y.sec].append(Func(y, y.sec.name, data, y.value))
        for funcs in code.values():
            funcs.sort(key=lambda f: f.start)
        starts = {s: [f.start for f in funcs] for s, funcs in code.items()}

        def func_at(sec, off):
            i = bisect_right(starts[sec], off) - 1
            if i < 0 or off != starts[sec][i]:
                raise Err('reference to %s+%d: no function starts there' % (sec.name, off))
            return code[sec][i]

        self.funcs, self.ptrs = [], []
        for s, funcs in code.items():
            s.rels.sort(key=lambda r: r.off)
            offs = [r.off for r in s.rels]
            have = set(offs)
            near = [p for p in find_insns(s.data, PSEUDO_CALL) if p not in have]
            recs = [t.pop(s.name, array('I')) for t in tables]
            rec_offs = [r[::n] for r, n in zip(recs, EXT_WORDS)]
            for f in funcs:
                lo, hi = f.start, f.start + len(f.data)
                for r in s.rels[bisect_left(offs, lo):bisect_left(offs, hi)]:
                    if r.sym.sec in code:
                        imm = get_imm(s.data, r.off)
                        add = (imm + 1) * 8 if s.data[r.off] == CALL else imm
                        f.calls.append([r.off - lo, func_at(r.sym.sec, r.sym.value + add)])
                    else:
                        f.rels.append(Rel(r.off - lo, r.sym, r.type))
                for p in near[bisect_left(near, lo):bisect_left(near, hi)]:
                    f.calls.append([p - lo, func_at(s, p + (get_imm(s.data, p) + 1) * 8)])
                for k, n in enumerate(EXT_WORDS):
                    x = recs[k][bisect_left(rec_offs[k], lo) * n:bisect_left(rec_offs[k], hi) * n]
                    f.ext[k] = shift(x, n, -lo)
            self.funcs += funcs
        self.secs = [s for s in self.secs if s not in code and s is not btf and s is not ext]
        for s in self.secs:
            for r in s.rels:
                if r.sym.sec in code:
                    add, = struct.unpack_from('<Q', s.data, r.off)
                    self.ptrs.append([s, r.off, func_at(r.sym.sec, r.sym.value + add)])
            s.rels = [r for r in s.rels if r.sym.sec not in code]
        self.syms = [y for y in self.syms if y.sec not in code and y.type != FILE]

    def progs(self):
        return [f for f in self.funcs if f.entry]

    def rels(self):
        for x in self.funcs + self.secs:
            yield from x.rels

    def write(self, path):
        used = {r.sym for r in self.rels()}
        self.syms = [y for y in self.syms if y in used or
                     not (y.bind == LOCAL and y.type in (NOTYPE, SECTION))]
        code = {}
        for f in sorted(self.funcs, key=lambda f: f.entry):
            if f.sec not in code:
                code[f.sec] = Sec(f.sec, flags=SHF_ALLOC | SHF_EXECINSTR, align=8)
            f.sym.sec, f.sym.size = code[f.sec], len(f.data)
            f.sym.value = len(f.sym.sec.data)
            f.sym.sec.data += f.data
        self.move_jump_tables()
        text = Sym('', LOCAL, SECTION, sec=code.get('.text'))
        tables = [{}, {}, {}]
        for f in self.funcs:
            s, base = f.sym.sec, f.sym.value
            s.rels += [Rel(r.off + base, r.sym, r.type) for r in f.rels]
            for off, to in f.calls:
                off, call = off + base, f.data[off] == CALL
                if to.sym.bind != LOCAL:
                    sym, add = to.sym, 0
                elif call and not f.entry:
                    sym, add = None, to.sym.value - off - 8
                else:
                    sym, add = text, to.sym.value
                set_imm(s.data, off, add // 8 - bool(sym) if call else add)
                if sym:
                    s.rels.append(Rel(off, sym, R_CALL if call else R_LD64))
            for k, n in enumerate(EXT_WORDS):
                if f.ext[k]:
                    tables[k].setdefault(f.sec, array('I')).extend(shift(f.ext[k], n, base))
        for s, off, to in self.ptrs:
            local = to.sym.bind == LOCAL
            struct.pack_into('<Q', s.data, off, to.sym.value if local else 0)
            s.rels.append(Rel(off, text if local else to.sym, R_ABS64))
        self.secs[:0] = code.values()
        for s in self.secs:
            s.rels.sort(key=lambda r: r.off)
        self.syms += [f.sym for f in self.funcs]
        if text.sec:
            self.syms.insert(0, text)
        if self.btf:
            self.write_btf(tables)
        super().write(path)

    def move_jump_tables(self):
        old = self.sec('.jumptables')
        if not old:
            return
        new = Sec(old.name, old.type, old.flags, old.align)
        self.secs[self.secs.index(old)] = new
        self.syms = [y for y in self.syms if y.sec is not old]
        for f in self.funcs:
            done = {}
            for r in f.rels:
                y = r.sym
                if y.sec is not old:
                    continue
                if y not in done:
                    done[y] = Sym(y.name, y.bind, y.type, y.other, new, len(new.data), y.size)
                    self.syms.append(done[y])
                    w = array('Q', bytes(old.data[y.value:y.value + y.size]))
                    new.data += array('Q', [x - f.start + f.sym.value for x in w]).tobytes()
                r.sym = done[y]
        if not new.data:
            self.secs.remove(new)

    def write_btf(self, tables):
        # gcc writes the absolute path of a source file
        strs, old = Strings(), lambda off: re.sub(r'^/.*?/src/[^/]+/(?=\S+$)', './', self.btf.str(off))
        types = self.btf.raw_types(strs)
        hdr, body = [], array('I')
        for k, n in enumerate(EXT_WORDS):
            start = len(body)
            if tables[k]:
                body.append(4 * n)
            for name, recs in tables[k].items():
                for col in ((), (1, 2), (2,))[k]:
                    offs = recs[col::n]
                    new = {x: strs[old(x)] for x in sorted(set(offs))}
                    recs[col::n] = array('I', map(new.__getitem__, offs))
                body.extend((strs[name], len(recs) // n))
                body.extend(recs)
            hdr += [4 * start, 4 * (len(body) - start)]
        self.secs.append(Sec('.BTF', align=4, data=struct.pack(
            '<HBBIIIII', 0xeb9f, 1, 0, 24, 0, len(types), len(types), len(strs.data)) +
            types + strs.data))
        if body:
            self.secs.append(Sec('.BTF.ext', align=4, data=struct.pack(
                '<HBBI6I', 0xeb9f, 1, 0, 32, *hdr) + body.tobytes()))


def shift(recs, words, delta):
    """A copy of the records with delta added to the offsets of the insns."""
    recs = recs[:]
    if delta:
        recs[::words] = array('I', [x + delta for x in recs[::words]])
    return recs
