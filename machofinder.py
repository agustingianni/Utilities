"""
Hacky script to gather all the mach-o file (and fat).
It prints the union of all the used load commands in all
the files found in the system.

Author: Agustin Gianni (agustingianni@gmail.com)
"""
import os
import struct
import shutil
import pickle

from macholib.MachO import MachO

#define FAT_MAGIC   0xcafebabe
#define FAT_CIGAM   0xbebafeca /* NXSwapLong(FAT_MAGIC) */
#define MH_MAGIC    0xfeedface /* the mach magic number */
#define MH_CIGAM    0xcefaedfe /* NXSwapInt(MH_MAGIC) */
#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */

# magics = [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca]
# magics = [0xfeedface, 0xfeedfacf]

def is_interesting(filepath, magics):
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

sect_type = {}
sect_type[0] = "S_REGULAR"
sect_type[1] = "S_ZEROFILL"
sect_type[2] = "S_CSTRING_LITERALS"
sect_type[3] = "S_4BYTE_LITERALS"
sect_type[4] = "S_8BYTE_LITERALS"
sect_type[5] = "S_LITERAL_POINTERS"
sect_type[6] = "S_NON_LAZY_SYMBOL_POINTERS"
sect_type[7] = "S_LAZY_SYMBOL_POINTERS"
sect_type[8] = "S_SYMBOL_STUBS"
sect_type[9] = "S_MOD_INIT_FUNC_POINTERS"
sect_type[10] = "S_MOD_TERM_FUNC_POINTERS"
sect_type[11] = "S_COALESCED"
sect_type[12] = "S_GB_ZEROFILL"
sect_type[13] = "S_INTERPOSING"
sect_type[14] = "S_16BYTE_LITERALS"
sect_type[15] = "S_DTRACE_DOF"
sect_type[16] = "S_LAZY_DYLIB_SYMBOL_POINTERS"
sect_type[17] = "S_THREAD_LOCAL_REGULAR"
sect_type[18] = "S_THREAD_LOCAL_ZEROFILL"
sect_type[19] = "S_THREAD_LOCAL_VARIABLES"
sect_type[20] = "S_THREAD_LOCAL_VARIABLE_POINTERS"
sect_type[21] = "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS"

def get_macho_section_types(filepath):
    section_types = set()

    try:    
        macho = MachO(filepath)
    
    except (ValueError, struct.error, IOError):
        return set()

    for header in macho.headers:
        for command in header.commands:
            try:
                if command[1].nsects:
                    # print command[1]
                    for sect in command[2]:
                        segname = sect.segname.replace("\x00", "")
                        sectname = sect.sectname.replace("\x00", "")
                        # print "  ", sect_type[sect.flags & 0xff], segname, sectname

                    # print "-" * 80
                    section_types.add(sect_type[sect.flags & 0xff])

            except AttributeError, e:
                pass

    return section_types

def get_macho_section_name(filepath):
    section_types = set()

    try:    
        macho = MachO(filepath)
    
    except (ValueError, struct.error, IOError):
        return set()

    for header in macho.headers:
        for command in header.commands:
            try:
                if command[1].nsects:
                    for sect in command[2]:
                        if sect.size:
                            segname = sect.segname.replace("\x00", "")
                            sectname = sect.sectname.replace("\x00", "")
                            section_types.add("%s.%s" % (segname, sectname))

            except AttributeError, e:
                pass

    return section_types

def print_all_used_load_commands(results):
    print "Global list of used load commands"
    print "-" * 80
    for command in sorted(set.union(*map(get_macho_load_commands, results))):
        print command
    print "-" * 80

    print "Number of files %d" % len(results)

def print_one_file_for_each_load_command(results):
    seen_commands = set()
    for path in results:
        if "Applications" in path:
            continue

        for load_command in get_macho_load_commands(path):
            if load_command in seen_commands:
                continue

            seen_commands.add(load_command)
            print "command %-30s -> %s" % (load_command, path)
            
            try:
                shutil.copyfile(path, os.path.join("/Users/anon/workspace/retools/src/libbinary/macho/testfiles", "test_load_command_%s" % load_command.lower()))

            except:
                continue

def print_one_file_for_each_section_type(results):
    seen_section_types = set()
    for path in results:
        if "Applications" in path:
            continue

        diff = get_macho_section_types(path) - seen_section_types

        if len(diff):
            seen_section_types.update(diff)
            print "%s -> [%s]" % (path, ", ".join(diff))

            for new_type in diff:
                try:
                    shutil.copyfile(path, os.path.join("/Users/anon/workspace/retools/src/libbinary/macho/testfiles", "test_section_type_%s" % new_type.lower()))
                except:
                    continue

def print_one_file_for_each_section_name(results):
    seen_section_types = set()
    for path in results:
        if "Applications" in path:
            continue
        diff = get_macho_section_name(path) - seen_section_types

        if len(diff):
            seen_section_types.update(diff)
            for new_type in diff:
                if "__DWARF" in new_type:
                    print "%-40s" % new_type, path
                    # try:
                    #     shutil.copyfile(path, os.path.join("/Users/anon/workspace/retools/src/libbinary/macho/testfiles/section_names", "test_section_name_%s" % new_type))
                    # except:
                    #     continue

def get_macho_filetype(filepath):
    try:    
        macho = MachO(filepath)
    
    except (ValueError, struct.error, IOError):
        return set()

    types = set()
    for header in macho.headers:
        types.add(header.filetype)

    return types

def print_onefile_for_each_filetype(results):
    seen_filetypes = set()
    for path in results:
        filetypes = get_macho_filetype(path)
        diff = filetypes - seen_filetypes

        if len(diff):
            print path, diff
            seen_filetypes.update(diff)

def locate_macho_files(root):
    results = []
    for root, subFolders, files in os.walk(root):
        for name in files:
            abs_name = os.path.join(root, name)
            if os.path.isfile(abs_name) and is_interesting(abs_name, [0xfeedface, 0xfeedfacf]):
                results.append(abs_name)

    return results

def locate_fat(root):
    i = 0
    results = []
    for root, subFolders, files in os.walk(root):
        for name in files:
            i += 1
            if not i % 5000:
                print "Processed %d files ..." % i
            
            abs_name = os.path.join(root, name)
            if os.path.isfile(abs_name) and is_interesting(abs_name, [0xcafebabe, 0xbebafeca]):
                results.append(abs_name)

    return results

def locate_big_endian(root):
    i = 0
    results = []
    for root, subFolders, files in os.walk(root):
        for name in files:
            i += 1
            if not i % 5000:
                print "Processed %d files ..." % i
            
            abs_name = os.path.join(root, name)
            if os.path.isfile(abs_name) and is_interesting(abs_name, [0xcefaedfe, 0xcffaedfe]):
                results.append(abs_name)

    return results

def print_segment_section_names(results):
    a = set()
    for filepath in results:
        try:    
            macho = MachO(filepath)
        
        except (ValueError, struct.error, IOError):
            continue

        for header in macho.headers:
            for command in header.commands:
                try:
                    if command[1].nsects:
                        #print command[1]
                        for sect in command[2]:
                            segname = sect.segname.replace("\x00", "")
                            sectname = sect.sectname.replace("\x00", "")
                            sectype = sect_type[sect.flags & 0xff]
                            #a.add((segname, sectname, sectype))
                            print sectype, segname, sectname, filepath

                except AttributeError, e:
                    pass

    # print "Results:"
    # for r in a:
    #     print "%s %s %s" % (r[0], r[1], r[2])

def get_smallest_macho(files):
    files_with_sizes = []

    import os
    import hashlib

    for file in files:
        if "invalid" in file or "svn" in file:
            continue

        try:
            cur_size = os.path.getsize(file)
        
        except OSError:
            continue

        files_with_sizes.append((cur_size, file))

    for el in sorted(files_with_sizes)[:10000]:
        dest_file = os.path.join("/Users/anon/fuzzing/afl-2.10b/macho_inputs", hashlib.md5(el[1]).hexdigest())
        try:
            shutil.copyfile(el[1], dest_file)

        except:
            continue

# if not os.path.exists("saved.bigendian.paths.db"):
#     print "Saving to disk!"
#     output = open("saved.bigendian.paths.db", "wb")
#     results = locate_big_endian("/")
#     pickle.dump(results, output)
#     print "Found %d fat big endian files" % len(results)

results = []
if not os.path.exists("saved.macho.paths.db"):
    print "Saving to disk!"
    output = open("saved.macho.paths.db", "wb")
    results = locate_macho_files("/")
    pickle.dump(results, output)
    print "Found %d macho files" % len(results)

results = pickle.load(open("saved.macho.paths.db", "rb"))
print "Found %d macho files" % len(results)
get_smallest_macho(results)