#!/usr/bin/env python
# 
# Author: Dave Hull
# License: We don't need no stinking license. I hereby place
# this in the public domain.
#
# Todo: 
# 
# It's a secret.

# Args: arguments
# Returns: none
# Checks the arguments to make sure they are sane
def check_args(args):
    print "[+] Checking command line arguments."

    try:
        fi = open(args.filename, 'rb')
    except:
        print "[+] Could not open %s for reading." % (args.filename)
        parser.print_help()
        quit()
    if fi.read(1) == '0':
        print "[+] %s may be a bodyfile." % (args.filename)
    else:
        print "[+] %s does not appear to be a bodyfle." % (args.filename)
        parser.print_help()
        quit()
    fi.close()

    if args.meta not in ['uid', 'gid']:
        print "[+] Invalid --meta argument: %s" % args.meta
        parser.print_help()
        quit()

    return

# Args: filename
# Returns: Dictionary of dictionaries containing paths, paths contain files
# files contain metadata for each file.
def get_meta(bodyfile):
    fname_skip_cnt = bad_line = total_lines = 0
    meta = {}

    fi = open(bodyfile, 'rb')
    for line in fi:
        total_lines += 1
        try: 
            md5,ppath,inode,mode,uid,gid,size,atime,mtime,ctime,crtime = line.rstrip().split("|")
        except:
            bad_line += 1
            continue

        fname = os.path.basename(ppath).rstrip()
        if fname == ".." or fname == ".":
            fname_skip_cnt += 1
            continue

        pname = os.path.dirname(ppath).rstrip()
        if pname not in meta:
            meta[pname] = {}

        meta[pname][fname] = {}
        meta[pname][fname]['uid'] = uid
        meta[pname][fname]['gid'] = gid

    print "[+] Discarded %d files named .. or ." % (fname_skip_cnt)
    print "[+] Discarded %d bad lines from %s." % (bad_line, args.filename)
    print "[+] Added %d paths to meta." % (len(meta))

    return meta

# Args: sorted directory listing contain unsorted dictionary 
# of files & meta data
# Returns: none
# Displays the distribution and probability of uid/gid for 
# files on a per directory basis. This has proven useful in 
# cases where an attacker has installed new files, but 
# neglected to change the uid/gid values to reflect the 
# "normal" values for the given directory.
def print_ugid_freq_by_dir(items, id_type):
    for path_name, file_name in items:
        freq = {}
        files = [(filename, meta) for filename, meta in file_name.items()]
        files.sort()
        for filename, meta in files:
            ugid = int(meta[id_type])
            freq[ugid] = freq.get(ugid, 0) + 1
        
        # swap uid and cnt without clobbering uniques
        ugid_cnt = [(cnt, ugid) for ugid, cnt in freq.items()]
        ugid_cnt.sort()
        if len(ugid_cnt) > 1:
            print "\nPath: ",  path_name
            linesep = "--------------------------"
            print "Count\t%s\t%%" % id_type
            print linesep
            ttl_files = float(len(files))
            probability = {}
            for cnt, ugid in ugid_cnt:
                probability[ugid] = cnt / ttl_files
                print "%6d\t%5d\t%.2f%%" % (cnt, ugid, probability[ugid] * 100.0)
    return

# Args: dictionary
# Returns: sorted list of dictionaries
def get_meta_by_dir(dictionary):
    # Sort the dictionary, return a list of dictionaries
    items = [(pname, fname) for pname, fname in dictionary.items()]
    items.sort()
    return items

if __name__ == '__main__':
    import re, os, math, argparse, sys
    from time import gmtime, strftime 

    parser = argparse.ArgumentParser(description = \
        'This script parses an fls bodyfile and returns the uid or gid ' \
        'distribution on a per directory basis.')
    parser.add_argument('--file', help = 'An fls bodyfile, see The Sleuth ' \
        'Kit.', dest = 'filename', required = True)
    parser.add_argument('--meta', help = '--meta can be "uid" or "gid." ' \
        'Default is "uid"', dest = 'meta', default = 'uid')
    if len(sys.argv) == 1:
        parser.print_help()
        quit()
    args = parser.parse_args()

    check_args(args)

    files_meta = get_meta(args.filename)

    dir_sorted_meta = get_meta_by_dir(files_meta)
    print_ugid_freq_by_dir(dir_sorted_meta, args.meta)
