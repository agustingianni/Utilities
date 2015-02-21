"""
Stupid tool to infer what's the underlying structure used by a function.
Highly heuristic. Don't trust it blindly, just try to use what it
gives you and work from that.
"""
from idautils import *

def FunctionInstructionsBlocks(function):
    return filter(lambda x: isCode(GetFlags(x)), list(Heads(function.startEA, function.endEA)))

qualifier2size = { "byte" : 1, "word" : 2, "dword" : 4, "qword" : 8, "xmmword" : 8 }
def GetQualifierSize(qualifier):
    return qualifier2size[qualifier]

reg128 = ["xmm0", "xmm1", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9"]
reg64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]
reg32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
reg16 = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
reg8 = ["ah", "al", "bh", "bl", "ch", "cl", "dh", "dl", "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]

def GetRegisterSize(register):
    if register in reg128:
        return 16
    elif register in reg64:
        return 8
    elif register in reg32:
        return 4
    elif register in reg16:
        return 2
    elif register in reg8:
        return 1

    raise Exception("Invalid register name: %s" % register)

def GuessSize(ea):
    """
    Fuck you IDA.
    """
    if GetOpType(ea, 0) == o_displ and "ptr" in GetOpnd(ea, 0):
        return GetQualifierSize(GetOpnd(ea, 0).split()[0])

    if GetOpType(ea, 1) == o_displ and "ptr" in GetOpnd(ea, 1):
        return GetQualifierSize(GetOpnd(ea, 1).split()[0])

    if GetOpType(ea, 0) == o_reg:
        return GetRegisterSize(GetOpnd(ea, 0))

    if GetOpType(ea, 1) == o_reg:
        return GetRegisterSize(GetOpnd(ea, 1))

    raise Exception("Cannot guess the size of ins: '%s'" % GetDisasm(ea))

ea = ScreenEA()
cur_func = get_func(ea)

base_reg = AskStr("r15", "What's the register used as the base for the struct access?.").lower()
size = AskLong(0, "Enter the size of the structure, leave 0 if unknown.")

offsets = []

for ea in FunctionInstructionsBlocks(cur_func):
    # Filter instructions that do not touch our base register.
    dis = GetDisasm(ea)
    if not base_reg in dis.lower():
        continue

    if GetOpType(ea, 0) == o_displ and base_reg in GetOpnd(ea, 0).lower():
        offsets.append((GetOperandValue(ea, 0), GuessSize(ea), ("0x%.8x: " % ea) + GetDisasm(ea)))

    if GetOpType(ea, 1) == o_displ and base_reg in GetOpnd(ea, 1).lower():
        offsets.append((GetOperandValue(ea, 1), GuessSize(ea), ("0x%.8x: " % ea) + GetDisasm(ea)))


size2type = {1 : "uint8_t", 2 : "uint16_t", 4 : "uint32_t", 8 : "uint64_t", 16 : "__m128"}
def GuessField(i, offset, size):
    if size in size2type.keys():
        return "%-8s fld_%d;" % (size2type[size], i)


    return "%-8s pad_%d[%d];" % ("uint8_t", i, size)


def MakeUnique(offsets):
    unique = []

    prev_o = -1
    prev_s = -1

    for a in offsets:
        if prev_o == -1:
            unique.append(a)
            prev_o = a[0]
            prev_s = a[1]
            continue

        if prev_o == a[0] and prev_s != a[1]:
            raise Exception("Conflict found at offset %.8x with sizes %d and %d" % (prev_o, prev_s, a[1]))

        elif prev_o != a[0]:
            unique.append(a)

        prev_o = a[0]
        prev_s = a[1]

    return unique

offsets = sorted(offsets, key=lambda tup: tup[0])

print "// User size: 0x%.4x" % size
print "// Inferred size: 0x%.4x" % (offsets[-1][0] + offsets[-1][1])
print "struct UnknownStructure {"

i = 0
cur_offset = 0
for a in MakeUnique(offsets):
    if cur_offset != a[0]:
        print "    %-20s // off=%.2xh-%.2xh reason=padding" % (GuessField(i, cur_offset, a[0] - cur_offset), cur_offset, a[0])
        i += 1

    cur_offset = a[0] + a[1]
    print "    %-20s // off=%.2xh-%.2xh reason=%s" % (GuessField(i, a[0], a[1]), a[0], a[0] + a[1], a[2])
    i += 1

# Check if the user hinted the final size and pad it if needed.
if size != 0 and size != offsets[-1][0] + offsets[-1][1]:
    rem_size = size - (offsets[-1][0] + offsets[-1][1])
    offset = offsets[-1][0] + offsets[-1][1]
    print "    %-20s // off=%.2xh-%.2xh reason=padding" % (GuessField(i, offset, rem_size), offset, rem_size)

print "};"
