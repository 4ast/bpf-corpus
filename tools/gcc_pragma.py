# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
"""gcc_pragma.py FILE.i

gcc does not know '#pragma clang attribute push (preserve_access_index)'.
Put the attribute on each definition of a struct or union up to the pop.
Give the CO-RE builtins the arguments that gcc takes.
Old SEC() macros have '#pragma GCC diagnostic' inside of a declaration. Remove it.
"""
import itertools, re, sys

PRAGMA = re.compile(rb'^[ \t]*#[ \t]*pragma[ \t]+clang[ \t]+attribute[ \t]+(push|pop)\b(.*)$', re.M)
DEFINITION = re.compile(rb'''\b(struct|union)\b
    (?= (?: \s*__attribute__\s*\(\( (?: [^()] | \([^()]*\) )* \)\) )* \s* \w* \s* \{ )''', re.X)
DIAGNOSTIC = re.compile(rb'^#pragma GCC diagnostic .*$', re.M)


def closing(text, i):
    """The index behind the bracket that closes the one at i."""
    depth = 0
    for m in re.compile(r'[()]').finditer(text, i):
        depth += 1 if m[0] == '(' else -1
        if not depth:
            return m.end()


def core_builtins(text):
    """Old copies of bpf_core_read.h have only the forms that clang takes."""
    out, at, n = [], 0, itertools.count()
    cast = r'\(\s*(?:__)?typeof(?:__)?\s*\(((?:[^()]|\([^()]*\))*)\)\s*\*\s*\)\s*'
    var = lambda ty: '({ extern typeof(%s) *core_type_%d; core_type_%d; })' % (ty, *[next(n)] * 2)
    bitfields = set(re.findall(r'(\w+)\s*:\s*\d+\s*;', text))
    for m in re.finditer(r'__builtin_(preserve_(enum_value|type_info|field_info)|btf_type_id)\s*\(',
                         text):
        if m.start() < at:
            continue
        end = closing(text, m.end() - 1)
        args = text[m.end():end]
        if m[2] == 'enum_value':
            args = re.sub(r'^\s*\*\s*' + cast + r'(?=\(?\w+\)?\s*,)',
                          lambda x: var(x[1]) + ', ', args)
        args = re.sub(cast + r'0\b', lambda x: var(x[1]), args)
        args = re.sub(r'^\s*\(&(\(.*\b(\w+)\))\)(?=\s*,[^,]*$)',
                      lambda x: x[1] if x[2] in bitfields else x[0], args, flags=re.S)
        out += [text[at:m.end()], args]
        at = end
    return ''.join(out) + text[at:]


def main(path):
    with open(path, 'rb') as f:
        text = DIAGNOSTIC.sub(b'', f.read())
    parts = PRAGMA.split(text)      # text, push or pop, arguments, text, ..
    out, stack = [parts[0]], []
    for op, args, text in zip(parts[1::3], parts[2::3], parts[3::3]):
        if op == b'push':
            stack.append(b'preserve_access_index' in args)
        elif stack:
            stack.pop()
        if any(stack):
            text = DEFINITION.sub(rb'\1 __attribute__((preserve_access_index))', text)
        out.append(text)
    with open(path, 'wb') as f:
        f.write(core_builtins(b''.join(out).decode('latin-1')).encode('latin-1'))


if __name__ == '__main__':
    main(sys.argv[1])
