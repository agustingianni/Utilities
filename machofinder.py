"""
Hacky script to gather all the mach-o file (and fat).
It prints the union of all the used load commands in all
the files found in the system.
"""
import os
import struct
from macholib.MachO import MachO

#define FAT_MAGIC   0xcafebabe
#define FAT_CIGAM   0xbebafeca /* NXSwapLong(FAT_MAGIC) */
#define MH_MAGIC    0xfeedface /* the mach magic number */
#define MH_CIGAM    0xcefaedfe /* NXSwapInt(MH_MAGIC) */
#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */

magics = [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca]

def is_interesting(filepath):
    try:
        data = open(filepath).read(4)
        magic = struct.unpack("<L", data)[0]

    except (struct.error, IOError):
        return False

    return magic in magics

def get_macho_load_commands(filepath):
    commands = set()

    try:    
        macho = MachO(filepath)
    
    except (ValueError, struct.error):
        return set()

    for header in macho.headers:
        for command in header.commands:
            commands.add(command[0].get_cmd_name())

    return commands

results = []
for root, subFolders, files in os.walk("/usr/local/bin"):
    for name in files:
        abs_name = os.path.join(root, name)
        if os.path.isfile(abs_name) and is_interesting(abs_name):
            results.append(abs_name)

print "Global list of used load commands"
print "-" * 80
for command in sorted(set.union(*map(get_macho_load_commands, results))):
    print command
print "-" * 80

print "Number of files %d" % len(results)