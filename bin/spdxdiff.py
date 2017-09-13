#!/usr/bin/python

# from linutronix.de elbe

from __future__ import absolute_import
from __future__ import print_function

from argparse import ArgumentParser
import csv
import copy
import sys


class spdxdata(object):
    def __init__(self, fname):
        self.fname = fname
        self.parser = ''
        self.filerefs = {}
        self.files = set()


class filedata(object):
    def __init__(self, fname, info=None):
        self.fname = fname
        self.licinfo = []
        self.concluded = ''
        if info:
            self.licinfo.append(info)


# Trivial SPDX scan
def read_spdx(filename, spdx):
    with open(filename) as f:
        fname = None
        for line in f.readlines():

            parts = line.split(':', 1)
            key = parts[0].strip()

            if key == 'Creator':
                parts = line.split(':', 2)
                if parts[1].strip() == 'Tool':
                    spdx.parser = parts[2].strip()

            if key == 'FileName':
                if fname:
                    # ??????
                    spdx.filerefs[fname] = fdata

                fname = parts[1].strip()
                # fix scancode % encoded paths
                fname = (fname.replace(',', '%2C').replace('+', '%2B'))
                fname = fname.split('/', 1)[1].strip()
                fdata = filedata(fname)

            if key == 'LicenseConcluded':
                lic = parts[1].strip()
                if lic == 'NONE':
                    lic = 'NOASSERTION'
                fdata.concluced = lic

            if key == 'LicenseInfoInFile':
                lic = parts[1].strip()
                if lic == 'NONE':
                    lic = 'NOASSERTION'
                if lic not in fdata.licinfo:
                    fdata.licinfo.append(lic)

        if fname:
            spdx.filerefs[fname] = fdata


# LID CSV scan
def read_csv(filename, spdx):

    spdx.parser = 'LID'

    with open(filename) as f:
        rdr = csv.reader(f)
        i = 0

        for row in rdr:
            i += 1
            if i == 1:
                continue

            fn = row[0].split('/', 1)[1].strip().replace(',', '%2C')
            lic = row[1]

            fd = spdx.filerefs.pop(fn, filedata(fn))
            if lic not in fd.licinfo:
                fd.licinfo.append(lic)
            spdx.filerefs[fn] = fd


def diff_spdx(spdxfiles, totfiles=0):
    """
    Diff two or more SPDX tag/value files in a list of `spdxfiles` paths
    and print the result to stdout as CSV.

    For spdx.windriver.com make sure you use the SPDX 2.0 service.
    For ScanCode make sure you use --strip-root when scanning.

    Optionally include `totfiles` which is the real number of files that
    should have been scanned.
    """
    spdx = {}
    files = set()

    t = 'Tool %d' % totfiles
    for spf in spdxfiles:
        s = spdxdata(spf)

        if spf.endswith('.spdx'):
            read_spdx(spf, s)
        else:
            raise Exception('NOT an SPDX file: ' + spf)

        s.files = set(sorted(s.filerefs.keys()))
        files = files | s.files
        spdx[spf] = s
        t += ',' + s.parser + ':%d' % (len(s.files))

    t += ',Match'

    print(t)

    for src in sorted(files):
        info = src
        lics = None
        match = 'Y'
        for spf in spdxfiles:
            li = spdx[spf].filerefs.get(src, filedata(src, 'NOTSCANNED')).licinfo
            if not lics:
                lics = copy.copy(li)
            # ignore case as some licenseref are identical ignoring case
            elif set(l.lower() for l in lics) != set(l.lower() for l in li):
                match = ''

            info += ','
            # sort licenses for better visual comparison
            licsv = ' '.join(sorted(li))
            info += licsv
        print(info + ',' + match)


description = """
Diff two or more SPDX Tag-value files produced by different scanners.

The input is two or more SPDX tag-value files with an .spdx extension.

The output is a CSV  printed to stdout.

Supported scanners are ScanCode, the WR SPDX 2.0 and Fossology.
"""


if __name__ == '__main__':
    parser = ArgumentParser(description=description)
    parser.add_argument('filenames', metavar='file', nargs='+',
                        help='list of paths, minimum 2')
    parser.add_argument('-s', '--sourcefiles', type=int, default=0,
                        help='Number of files in the source')

    args = parser.parse_args()

    if len(args.filenames) < 1:
        print('Not enough SPDX files: need at least two\n')
        sys.exit(1)

    diff_spdx(args.filenames, args.sourcefiles)
