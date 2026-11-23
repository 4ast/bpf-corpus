#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
"""compare.py OLD.csv NEW.csv [N]: lost and gained programs, the N largest changes of insns

The exit code is 1 if a program does not load any more. 'veristat -C' takes the same files.
"""
import collections, csv, lzma, re, sys


def read(path):
    f = lzma.open(path, 'rt') if path.endswith('.xz') else open(path)
    return {(r['file_name'], r['prog_name']): (r['verdict'] == 'success', int(r['total_insns']))
            for r in csv.DictReader(f)}


if len(sys.argv) < 3:
    sys.exit(__doc__)
old, new = read(sys.argv[1]), read(sys.argv[2])
top = int(sys.argv[3]) if len(sys.argv) > 3 else 10
both = sorted(old.keys() & new.keys())
stat = collections.defaultdict(collections.Counter)
for k in both:
    (a, x), (b, y) = old[k], new[k]
    for s in stat[re.match(r'[a-z0-9-]+?(?=-v?\d+\.|\.)', k[0])[0]], stat['TOTAL']:
        s.update(progs=1, old=a, new=b, lost=a and not b, gained=b and not a)
        if a and b:
            s.update(x=x, y=y)
print('%-24s %8s %8s %8s %6s %6s %8s' % ('project', 'progs', 'old', 'new', 'lost', 'gained', 'insns'))
for p, s in sorted(stat.items(), key=lambda i: (i[0] == 'TOTAL', i[0])):
    print('%-24s %8d %8d %8d %6d %6d %+7.2f%%' % (p, s['progs'], s['old'], s['new'], s['lost'],
          s['gained'], 100 * (s['y'] - s['x']) / max(s['x'], 1)))
for name, a, b in ('LOST', True, False), ('GAINED', False, True):
    for k in both:
        if (old[k][0], new[k][0]) == (a, b):
            print(name, *k)
diff = sorted((new[k][1] - old[k][1], k) for k in both if old[k][0] and new[k][0])
for d, k in diff[:top] + diff[-top:]:
    if d:
        print('INSNS %d -> %d' % (old[k][1], new[k][1]), *k)
if len(both) != len(old) or len(both) != len(new):
    print('only in old: %d, only in new: %d' % (len(old) - len(both), len(new) - len(both)))
sys.exit(stat['TOTAL']['lost'] > 0)
