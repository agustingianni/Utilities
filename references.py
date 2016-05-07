from collections import namedtuple
import idautils
from idc import GetFunctionName, GetDisasm, GetMnem, GetOpnd, Demangle, GetLongPrm, INF_SHORT_DN

__author__ = 'anon'

import idaapi

FunctionName = namedtuple('FunctionName', ['ea', 'name'])
ImportEntry = namedtuple('ImportEntry', ['ea', 'name', 'ord'])
BasicBlock = namedtuple('BasicBlock', ['start_ea', 'end_ea', 'function'])
FunctionSignature = namedtuple('FunctionSignature', ['name', 'nargs'])
Instruction = namedtuple('Instruction', ['ea', 'string'])
FunctionArgument = namedtuple('FunctionArgument', ['argument', 'instruction'])

imports_list = []
function_names = []


def EnumImportNamesCallback(ea, name, ord_):
    if name:
        imports_list.append(ImportEntry(ea, name, ord_))

    return True


def GetAllImportEntries():
    for i in xrange(0, idaapi.get_import_module_qty()):
        name = idaapi.get_import_module_name(i)
        if not name:
            pass

        idaapi.enum_import_names(i, EnumImportNamesCallback)

    return imports_list


def GetAllFunctionNames():
    func_name_list = []
    for x in idautils.Functions():
        func_name_list.append(FunctionName(x, GetFunctionDemangledName(x)))

    return func_name_list


def GetAddressBasicBlock(ea):
    f = idaapi.get_func(ea)
    if not f:
        raise RuntimeError("No basic block at address %.8x" % ea)

    for block in idaapi.FlowChart(f):
        if block.startEA <= ea and block.endEA > ea:
            return BasicBlock(block.startEA, block.endEA, f)

    raise RuntimeError("No basic block at address %.8x" % ea)

def GetInstructions(start_ea, end_ea):
    ins = []
    for head in idautils.Heads(start_ea, end_ea):
        if idaapi.isCode(idaapi.getFlags(head)):
            ins.append(Instruction(head, GetDisasm(head)))

    return ins

def IsArgumentSetter(ea):
    if GetMnem(ea).lower() == "push":
        return True

def GetFunctionArgument(ins):
    opnd = GetOpnd(ins.ea, 0)
    return FunctionArgument(opnd, ins)

def GetFunctionCallArguments(func_sig, xref_addr):
    args = []
    bb = GetAddressBasicBlock(xref_addr)

    instructions = GetInstructions(bb.start_ea, bb.end_ea)
    instructions = filter(lambda x: x.ea <= xref_addr, instructions)

    if GetMnem(instructions[-1].ea).lower() not in ["call", "jmp"]:
        print instructions[-1]
        raise RuntimeError("Bullshit")

    n_found_args = 0
    for ins in reversed(instructions[:-1]):
        if n_found_args == func_sig.nargs:
            break

        if IsArgumentSetter(ins.ea):
            n_found_args += 1
            args.append(GetFunctionArgument(ins))

    return args

def GetFunctionDemangledName(xref_addr):
    tmp = GetFunctionName(xref_addr)
    name = Demangle(tmp, GetLongPrm(INF_SHORT_DN))
    return name if name else tmp

func_sig = FunctionSignature("operator new", 1)

interesting_functions = []

for a in GetAllFunctionNames():
    if func_sig.name in a.name:
        print a.name
        interesting_functions.append(a)

for a in GetAllImportEntries():
    if func_sig.name in a.name:
        interesting_functions.append(a)


InterestingResult = namedtuple('InterestingResult', ['caller_name', 'callee_name', 'call_address', 'arguments'])

results = []
for function in interesting_functions:
    # Get all code xrefs to
    xrefs = idautils.CodeRefsTo(function.ea, 0)
    for call_address in xrefs:
        arguments = GetFunctionCallArguments(func_sig, call_address)
        caller_name = GetFunctionDemangledName(call_address)
        callee_name = function.name

        results.append(InterestingResult(caller_name, callee_name, call_address, arguments))

        #print "// Calling function %s " % caller_name
        #print "// Call address 0x%.8x" % call_address
        #print "%s(%s);" % (function.name, ",".join(map(lambda x: '"%s"' % x.argument, arguments)))
        #print

def IDAArgumentToSize(arg):
    a = -1

    if arg[-1] in ['h', 'H']:

        a = int(arg[:-1], 16)

    else:
        try:
            a = int(arg, 10)

        except ValueError:
            a = -1

    return a

def sort_func(element):
    arg = element.arguments[0].argument
    return IDAArgumentToSize(arg)

# Sort by alloc size.
results.sort(key=sort_func, reverse=True)
for result in results:
    print "// Caller function %s " % result.caller_name
    print "// Call address    0x%.8x" % result.call_address
    print "// Alloc size      0x%.8x" % IDAArgumentToSize(result.arguments[0].argument)
    print "%s(%s);" % (result.callee_name, ",".join(map(lambda x: '"%s"' % x.argument, result.arguments)))
    print
