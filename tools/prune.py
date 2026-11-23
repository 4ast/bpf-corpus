#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
"""prune.py [-c NAME=PATH].. [-j N] [PROJECT..]: print the files that the compilers read

To add a project: put its tree into src/NAME, write src/NAME/jobs, and delete
what this list does not have, but keep the licence files.
"""
import argparse, multiprocessing, os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
import build


def deps(unit):
    job, cc, flavour, todo = unit
    target = ['-target', 'x86_64-linux-gnu'] if '--x86-ir' in job.flags else \
        cc.target + ['-mcpu=' + next(iter(todo))]
    files = set()
    for src in job.sources:
        p = subprocess.run([cc.path] + target + cc.flags(job, flavour) + ['-M', '-MG', src],
                           cwd=job.dir, capture_output=True, text=True)
        for f in re.split(r'(?<!\\)\s+', p.stdout.replace('\\\n', ' '))[1:]:
            # The path as it is spelled, and each symlink on the way.
            path = job.dir
            for part in f.replace('\\ ', ' ').split('/'):
                path = os.path.join(path, part) if part else '/'
                if os.path.islink(path):
                    files.add(os.path.join(os.path.realpath(os.path.dirname(path)), part))
            if os.path.isfile(path):
                files.add(os.path.realpath(path))
    return files


def main():
    ap = argparse.ArgumentParser(usage=__doc__)
    ap.add_argument('-c', action='append', default=[])
    ap.add_argument('-t', default='*-v?')
    ap.add_argument('-j', type=int, default=os.cpu_count())
    ap.add_argument('patterns', nargs='*')
    a = ap.parse_args()
    units = build.plan(a.patterns, build.find_compilers(a.c), a.t.split(','))
    with multiprocessing.get_context('fork').Pool(a.j) as pool:
        files = set().union(*pool.imap_unordered(deps, units, 8))
    for f in sorted(files):
        if f.startswith(build.TOP + '/') and not f.startswith(build.TOP + '/cc/'):
            print(os.path.relpath(f, build.TOP))


main()
