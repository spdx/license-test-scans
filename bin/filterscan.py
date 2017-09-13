#!/usr/bin/python

from argparse import ArgumentParser
from collections import OrderedDict
import json


def weird_match(lics):
    common_rules = set([
        'gpl-2.0-plus_47.RULE',
        'gpl-2.0-plus_105.RULE',
        'gpl_194.RULE',
        'gpl-2.0_124.RULE',
        'gpl-2.0_151.RULE',
        'gpl-2.0_358.RULE',
        'gpl-2.0_75.RULE',
        'gpl-2.0_105.RULE',
        'gpl-2.0_155.RULE',
        'gpl-2.0_171.RULE',
        'gpl-2.0_217.RULE',
        'gpl-2.0_300.RULE',
        'gpl_88.RULE',
        'gpl-2.0-plus_189.RULE',
        'gpl-2.0_491.RULE',
        'gpl_125.RULE',
        'gpl_96.RULE',
        'clear-bsd_or_gpl-2.0-plus.RULE',
        'clear-bsd_or_gpl-2.0-plus2.RULE',
        'clear-bsd_2.RULE',
        'bsd-new_or_gpl-2.0_1.RULE',
        'gpl_85.RULE',
        'gpl_72.RULE',
        'gpl_97.RULE',
        'gpl-2.0_106.RULE'])

    lics = (l for l in lics 
            if not l['score'] > 90)

    lics = (l for l in lics 
            if not l['matched_text'].startswith(
                ('MODULE_LICENSE', 'DRIVER_LICENSE', 'EXPORT_SYMBOL',)))

    lics = (l for l in lics 
            if not (l['score'] > 80 and len(l['matched_text']) > 100))

    lics = (l for l in lics 
            if not (l['matched_rule']['matcher'] == '1-aho' and
                    l['matched_rule']['identifier'] in common_rules))

    return list(lics)


def main(path_in, path_out):
    data = json.load(open(path_in, 'rb'), object_pairs_hook=OrderedDict)
    old_files = data['files']
    new_files = []
    for fil in old_files:
        lics = fil['licenses']
        lics = weird_match(lics)
        if not lics:
            continue
        fil['licenses'] = lics
        new_files.append(fil)

    data['files'] = new_files
    with open(path_out, 'wb') as o:
        json.dump(data, o, indent=2)


description = """Filter a Linux Kernel ScanCcode scan."""

if __name__ == '__main__':
    parser = ArgumentParser(description=description)
    parser.add_argument('path_in', metavar='path_in', help='JSON input')
    parser.add_argument('path_out', metavar='path_out', help='JSON output')
    args = parser.parse_args()
    main(args.path_in, args.path_out)
