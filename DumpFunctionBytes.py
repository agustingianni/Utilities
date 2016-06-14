"""
Script to dump the current function as a C/C++ shellcode blob.
It replaces the calls to external functions with a call to a
trampoline entry that you can change to point to your own implementation
of that function.

Author: Agustin Gianni (agustingianni@gmail.com)
"""

import sys
if not "/usr/local/lib/python2.7/site-packages" in sys.path:
    sys.path.append("/usr/local/lib/python2.7/site-packages")

from capstone import *
from capstone.x86_const import *
from binascii import hexlify

DEBUG = False

def to_hex(bytes, cformat=False):
    tmp = hexlify(bytes)
    if cformat:
        return "\\x" + "\\x".join([tmp[i:i+2] for i in range(0, len(tmp), 2)])

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

def make_call_immediate(offset):
    import struct
    return "\xe8" + struct.pack("<L", offset - 5)

def main():
    # Get the function from IDA.
    start, size, fbytes = dump_function_bytes(ScreenEA())

    # Collect and print debugging information about the function.
    to_replace = []
    invalid_jumps = []

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Disassemble the function.
    instructions = list(md.disasm(fbytes, 0))

    # Lambdas to query for interesting disassembly bits.
    is_jump = lambda i: X86_GRP_JUMP in i.groups
    is_imm_jump = lambda i: is_jump(i) and i.operands[0].type == X86_OP_IMM
    is_invalid_imm_jump = lambda i: i.operands[0].value.imm < start or i.operands[0].value.imm >= (start + size)
    is_call = lambda i: X86_GRP_CALL in i.groups
    is_ret  = lambda i: X86_GRP_RET in i.groups
    is_flow_changing = lambda i: is_jump(i) or is_call(i) or is_ret(i)

    # Instruction query results.
    jump_sites = filter(is_jump, instructions)
    imm_jump_sites = filter(is_imm_jump, instructions)
    call_sites = filter(is_call, instructions)
    ret_sites = filter(is_ret, instructions)
    invalid_jump_sites = filter(is_invalid_imm_jump, filter(is_imm_jump, jump_sites))

    # Collect information about jumps and calls that need manual work.
    jumps_to_fix = [(i.address, i) for i in invalid_jump_sites]
    calls_to_fix = [(i.address, i) for i in call_sites]

    # Collect the start of every basic block for pretty printing.
    basic_block_start = []
    basic_block_start.extend([i.address + i.size for i in (jump_sites + ret_sites)])
    basic_block_start.extend([i.operands[0].value.imm for i in imm_jump_sites])

    if DEBUG:
        # Debug dump of the function.
        print "// Function disassembly:"
        for i in instructions:
            if i.address in basic_block_start:
                print "// " + ("-" * 80) 
            print "// 0x%.8x: %-32s %-8s %s" %(i.address, to_hex(i.bytes), i.mnemonic, i.op_str)
    
        # Print a list of functions that need to be implemented for the blob to work.
        if len(calls_to_fix):
            print "// "
            print "// Function calls to replace:"
            for e in calls_to_fix:
                tmp = "%s %s" %(e[1].mnemonic, e[1].op_str)
                print "// off=0x%.8x ins='%s' bytes=%s size=%d imm=0x%.8x" % (e[0], tmp, to_hex(e[1].bytes), e[1].size, e[1].operands[0].value.imm)

        # Warn the user that the function is not complete and should be correctly extracted.
        if len(jumps_to_fix):
            print "// "
            print "// Invalid jumps:"
            for e in jumps_to_fix:
                tmp = "%s %s" %(e[1].mnemonic, e[1].op_str)
                print "// off=0x%.8x ins='%s' bytes=%s size=%d" % (e[0], tmp, to_hex(e[1].bytes), e[1].size)

    print '#include <string>'
    print '#include <iostream>'
    print '#include <sys/mman.h>\n'
    print 'using namespace std;\n'
    print 'string build_blob();\n'
    print 'void *alloc_rwx(size_t size) {'
    print '    void *mem = mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, 0, 0);'
    print '    if (!mem) {'
    print '        cout << "Could not alloc RWX memory." << endl;'
    print '        return nullptr;'
    print '    }\n'
    print '    cout << "Allocated RwX memory at: " << mem << endl;'
    print '    return mem;'
    print '}\n'
    print 'int main(int argc, char **argv) {'
    print '    string blob = build_blob();'
    print '    void *mem = alloc_rwx(blob.size());'
    print '    memcpy(mem, &blob[0], blob.size());\n'
    print '    // TODO: Change the signature of the function pointer.'
    print '    ((int (*)(void)) mem)();'
    print '}\n'
    print 'string build_blob() {'

    # Make the calls point to our dispatch table.
    print '    string dispatch_table;'
    imm_to_offset = {}
    cur_trampoline_offset = len(fbytes)

    for (call_off, call_ins) in calls_to_fix:
        operand = call_ins.operands[0]
        if operand.type != X86_OP_IMM:
            raise RuntimeException("We don't handle non immediate calls yet.")

        # Get the destination of the call.
        operand_imm = operand.value.imm

        # Check if we already have an entry for this immediate value.
        if not imm_to_offset.has_key(operand_imm):
            # Add the current offset to the dictionary.
            imm_to_offset[operand_imm] = cur_trampoline_offset

            tmp_name = "function_%d_address" % imm_to_offset[operand_imm]
            tmp = 'dispatch_table.append("\\x48\\xb8", 2);'
            print "    // TODO: Replace %s with the correct implementation." % tmp_name
            print "    uintptr_t %s = reinterpret_cast<uintptr_t>(0x4040404040404040);" % tmp_name
            print "    %-60s // 0x%.8x: movabs   rax, %s" % (tmp, cur_trampoline_offset, tmp_name)
            cur_trampoline_offset += 10

            tmp = 'dispatch_table.append("\\xff\\xe0", 2);'
            print "    dispatch_table.append(reinterpret_cast<const char *>(&%s), sizeof(%s));" % (tmp_name, tmp_name)
            print "    %-60s // 0x%.8x: jmp      rax" % (tmp, cur_trampoline_offset)
            print
            cur_trampoline_offset += 2

        # Get the trampoline offset for the current immediate.
        trampoline_offset = imm_to_offset[operand_imm]

        # Adjust the trampoline offset with the offset of the current call.
        trampoline_offset -= call_off

        # Create a trampoline call and replace the original call.
        trampoline_call = make_call_immediate(trampoline_offset)

        # Replace original call bytes.
        fbytes = fbytes[:call_off] + trampoline_call + fbytes[call_off + len(trampoline_call):]

    print '    // Dumped [0x%.8x-0x%.8x]' % (start, start + size)
    print '    string shellcode;'
    instructions = list(md.disasm(fbytes, 0))
    for i in instructions:
        tmp = 'shellcode.append("%s", %d);' % (to_hex(i.bytes, cformat=True), len(i.bytes))
        print '    %-60s // 0x%.8x: %-8s %s' % (tmp, i.address, i.mnemonic, i.op_str)
    print

    print "    return shellcode + dispatch_table;"
    print "}"
    print

main()
