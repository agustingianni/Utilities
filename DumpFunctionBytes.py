"""
Script to dump the current function as a C/C++ shellcode blob.

Author: Agustin Gianni (agustingianni@gmail.com)
"""

from capstone import *
from capstone.x86_const import *
from binascii import hexlify

import sys
if not "/usr/local/lib/python2.7/site-packages" in sys.path:
    sys.path.append("/usr/local/lib/python2.7/site-packages")

def to_hex(bytes):
    tmp = hexlify(bytes)
    return " ".join([tmp[i:i+2] for i in range(0, len(tmp), 2)])

def dump_function_bytes(fn_ea, align=False):
    f = idaapi.get_func(fn_ea)
    start = f.startEA
    size = f.endEA - start
    contents = GetManyBytes(start, size)

    if align:
        rem = len(fbytes) % 32
        fbytes += "\xcc" * (32 - rem) if rem else ""

    return (start, size, contents)

def main():
    # Get the function from IDA.
    fn_ea = ScreenEA()
    start, size, fbytes = dump_function_bytes(fn_ea)

    # Collect and print debugging information about the function.
    to_replace = []
    invalid_jumps = []

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print "// Function details:"
    for i in md.disasm(fbytes, fn_ea):
        print "// 0x%.8x: %-32s %-8s %s" %(i.address, to_hex(i.bytes), i.mnemonic, i.op_str)
        for group in i.groups:
            if group in [X86_GRP_JUMP, X86_GRP_RET]:
                for op in i.operands:
                    if op.type == X86_OP_IMM:
                        if op.value.imm < start or op.value.imm >= (start + size):
                            invalid_jumps.append((i.address - fn_ea, i))

                print "//"

            elif group is X86_GRP_CALL:
                to_replace.append((i.address - fn_ea, i))

    print "// "
    print "// Functions to replace:"
    for e in to_replace:
        tmp = "// 0x%.8x: %-8s %s" %(e[1].address, e[1].mnemonic, e[1].op_str)
        print "// off=0x%.8x ins=%s bytes=%s size=%d" % (e[0], tmp, to_hex(e[1].bytes), e[1].size)

    print "// "
    print "// Invalid jumps:"
    for e in invalid_jumps:
        tmp = "// 0x%.8x: %-8s %s" %(e[1].address, e[1].mnemonic, e[1].op_str)
        print "// off=0x%.8x ins=%s bytes=%s size=%d" % (e[0], tmp, to_hex(e[1].bytes), e[1].size)

    # Dump a shellcode version of the function.
    print "// "
    print "// Dumped [0x%.8x-0x%.8x]" % (start, start + size)
    n_elements = len(fbytes) / 32

    print "unsigned char shellcode [] = \\"
    for i in range(0, len(fbytes), 32):
        print "\"%s\"" % "".join(["\\x%.2x" % ord(c) for c in fbytes[i : i + 32]])

main()
