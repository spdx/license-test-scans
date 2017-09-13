#!/usr/bin/python

# from linutronix.de elbe

from __future__ import print_function

from argparse import ArgumentParser
import sys
import os

min_file_size = 100
min_file_lines = 10

class scan(object):
    def __init__(self, p1, p2, pkgs):
        self.p1 = p1
        self.p2 = p2
        self.pkgs = pkgs

class spdxdata(object):
    def __init__(self, fname, ref):
        self.fname = fname
        self.packagename = ""
        self.parser = ""
        self.filerefs = {}
        self.files = set()
        self.ref = ref

        self.rfiles = 0
        self.rfiles_c = 0
        self.rfiles_l = 0

        self.tfiles = 0
        self.tfiles_c = 0
        self.tfiles_l = 0
        
        self.grade = 0

    def add_ref(self, fname, fdata):
        self.filerefs[fname] = fdata

        # Magic stats
        self.tfiles += 1
        if fdata.has_linfo() or fdata.has_cinfo():
            self.tfiles_l += 1

        if self.ref:
            refd = self.ref.filerefs.get(fname, None)
            fn = fname
            while not refd:
                try:
                    fn = fn.split("/", 1)[1]
                except:
                    break;
                try:
                    refd = self.ref.filerefs[fn]
                except:
                    continue

            if refd:
                fdata.is_source = refd.is_source
                fdata.size = refd.size
                fdata.lines = refd.lines
            else:
                print("No ref %s" %fname)
                pass
            
        # Relevant file?
        if fdata.size < min_file_size and fdata.lines < min_file_lines:
            return
        if not fdata.is_source:
                return

        self.rfiles += 1
        if fdata.has_linfo() or fdata.has_cinfo():
            self.rfiles_l += 1

class filedata(object):
    def __init__(self, fname, info=None):
        self.fname = fname
        self.licinfo = []
        self.concluded = ""
        if info:
            self.licinfo.append(info)
        self.size = 0
        self.lines = 0
        self.is_source = False
        self.proglang = "None"

    def has_linfo(self):
        if len(self.licinfo) > 1:
            return True
        return self.licinfo[0] != "NOASSERTION"

    def has_cinfo(self):
        return len(self.concluded) > 0 and self.concluded != "NOASSERTION"

# Trivial SPDX scan
def read_spdx(filename, spdx):

    with open(filename) as f:
        fdata = None
        for line in f.readlines():

            parts = line.split(":", 1)
            key = parts[0].strip()

            if key == 'Creator':
                parts = line.split(":", 2)
                if parts[1].strip() == 'Tool':
                    spdx.parser = parts[2].strip()

            if key == "PackageName":
                spdx.packagename = parts[1].strip()
                    
            if key == 'FileName':
                if fdata:
                    spdx.add_ref(fdata.fname, fdata)
                    fdata = None
                   
                fname = parts[1].strip()
                # fix scancode % encoded paths
                fname = (fname.replace(',', '%2C').replace('+', '%2B'))
                fname= fname.lstrip('./').strip()
                #fname = fname.split('/', 1)[1].strip()
                fdata = filedata(fname)

            if not fdata:
                continue

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

            if key == 'IsSource' and parts[1].find("True") >= 0:
                fdata.is_source = True

            if key == 'ProgLanguage':
                fdata.proglang = parts[1].strip()

            try:
                if key == 'Size':
                    fdata.size = int(parts[1].strip())

                if key == 'Lines':
                    fdata.lines = int(parts[1].strip())
            except:
                pass

        if fdata:
            spdx.add_ref(fdata.fname, fdata)

def set_grade(data, spdxref, spdxfos):
    if spdxref.rfiles:
        grade = 100 * spdxref.rfiles_l / spdxref.rfiles
        fgrade = 100 * spdxfos.rfiles_l / spdxref.rfiles
    else:
        grade = 0
        fgrade = 0

    if spdxref.tfiles:
        tgrade = 100 * spdxref.tfiles_l / spdxref.tfiles
        ftgrade = 100 * spdxfos.tfiles_l / spdxref.tfiles
    else:
        tgrade = 0 
        ftgrade = 0
       
    stat = "%s;%d;%d;%d;" %(spdxref.packagename, spdxref.tfiles, spdxref.tfiles_l, spdxfos.tfiles_l)
    stat +=   "%d;%d;%d;" %(spdxref.rfiles, spdxref.rfiles_l, spdxfos.rfiles_l)
    stat +=   "%d;%d;%d;%d\n" %(tgrade, ftgrade, grade, fgrade) 

    data.pkgs[spdxref.packagename] = stat
            
def process_dir(data, dirname, names):
    for name in names:
        path = os.path.join(dirname, name)
        if not os.path.isfile(path):
            continue

        spdxref = spdxdata(path, None)
        read_spdx(path, spdxref)

        fosn = path.replace(data.p1, data.p2)
        fosn = os.path.dirname(fosn)
        try:
            fns = os.listdir(fosn)
            fosn = os.path.join(fosn, fns.pop())
            spdxfos = spdxdata(fosn, spdxref)
            read_spdx(fosn, spdxfos)
        except Exception, ex:
            print(ex)
            spdxfos = spdxdata(path, True)
            print("No comparison for %s" %path)
        
        set_grade(data, spdxref, spdxfos)

if __name__ == '__main__':
    parser = ArgumentParser(description='Generate stats from SPDX file(s)')
    parser.add_argument('scancode', help='Scancode repository path')
    parser.add_argument('fossology', help='Fossology repository path')
    parser.add_argument('output', help='output path')

    args = parser.parse_args()

    if not os.path.isdir(args.scancode):
        print("{} not a directory".format(args.scancode))
        sys.exit(1)

    if not os.path.isdir(args.fossology):
        print("{} not a directory".format(args.fossology))
        sys.exit(1)

    sdata = scan(args.scancode, args.fossology, { })
    
    os.path.walk(args.scancode, process_dir, sdata)

    with open(args.output, 'w') as f:
        f.write("Package;Total files;License SC;License FO;Relevant files;License SC;License FO;Total %% SC;Total %% FO;Relevant %% SC;Relevant %% FO\n") 
        for k in sorted(sdata.pkgs):
            f.write(sdata.pkgs[k])
