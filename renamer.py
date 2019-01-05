"""
Rename files in a directory to its sha1 sum plus an extension.
"""
import os
import sys
import hashlib


def sha1_file(fn):
    f = open(fn, 'rb')
    r = hashlib.sha1(f.read()).hexdigest()
    f.close()
    return r


directory = os.path.abspath(sys.argv[1])
extension = sys.argv[2]

print "Doing directory `%s`" % directory

for fn in os.listdir(directory):
    if fn == ".DS_Store":
        continue

    orig_name = os.path.join(directory, fn)
    hexh = sha1_file(orig_name) + extension
    new_name = os.path.join(directory, hexh)

    print('%s -> %s' % (orig_name, new_name))

    os.rename(orig_name, new_name)
