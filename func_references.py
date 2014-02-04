"""
IDAPython script to search for a given function xreferences and its arguments.

The approach is very simple and probably wrong in many corner cases. We assume that
arguments are set via 'push' instructions and inside just one basic block (the basic
block that contains the function call).
"""

from collections import namedtuple
import idautils
from idc import GetFunctionName, GetDisasm, GetMnem, GetOpnd, Demangle, GetLongPrm, INF_SHORT_DN

__author__ = 'Agustin Gianni (agustin.gianni@gmail.com).'

import idaapi

FunctionName = namedtuple('FunctionName', ['ea', 'name'])
ImportEntry = namedtuple('ImportEntry', ['ea', 'name', 'ord'])
BasicBlock = namedtuple('BasicBlock', ['start_ea', 'end_ea', 'function'])
FunctionSignature = namedtuple('FunctionSignature', ['name', 'nargs'])
Instruction = namedtuple('Instruction', ['ea', 'string'])
FunctionArgument = namedtuple('FunctionArgument', ['argument', 'instruction'])
InterestingResult = namedtuple('InterestingResult', ['caller_name', 'callee_name', 'call_address', 'arguments'])

imports_list = []
function_names = []


def EnumImportNamesCallback(ea, name, ord_):
    """
    Callback used to enumerate all the import entries.
    """
    if name:
        imports_list.append(ImportEntry(ea, name, ord_))

    return True


def GetAllImportEntries():
    """
    Return a list of all the import entries.
    """
    for i in xrange(0, idaapi.get_import_module_qty()):
        name = idaapi.get_import_module_name(i)
        if not name:
            pass

        idaapi.enum_import_names(i, EnumImportNamesCallback)

    return imports_list


def GetAllFunctionNames():
    """
    Return a list of all the funtion names in the database.
    """
    func_name_list = []
    for x in idautils.Functions():
        func_name_list.append(FunctionName(x, GetFunctionDemangledName(x)))

    return func_name_list


def GetAddressBasicBlock(ea):
    """
    Get the corresponding basic block for a given address.
    """
    f = idaapi.get_func(ea)
    if not f:
        raise RuntimeError("No basic block at address %.8x" % ea)

    for block in idaapi.FlowChart(f):
        if block.startEA <= ea and block.endEA > ea:
            return BasicBlock(block.startEA, block.endEA, f)

    raise RuntimeError("No basic block at address %.8x" % ea)

def GetInstructions(start_ea, end_ea):
    """
    Return a list of all the instructions in the range [start_ea, end_ea].
    """
    ins = []
    for head in idautils.Heads(start_ea, end_ea):
        if idaapi.isCode(idaapi.getFlags(head)):
            ins.append(Instruction(head, GetDisasm(head)))

    return ins

def IsArgumentSetter(ea):
    """
    Architecture dependant utility function that assumes that all the push instructions
    ar argument setters.
    """
    if GetMnem(ea).lower() == "push":
        return True

def GetFunctionArgument(ins):
    """
    Architecture dependant function that takes an instruction and returns
    the function argument.
    In this case we assume that the first operand is the function argument (for push instructions).
    """
    opnd = GetOpnd(ins.ea, 0)
    return FunctionArgument(opnd, ins)

def IsFunctionCall(instruction):
    """
    Return true if the instruction 'ins' is a function call.
    """
    return GetMnem(instruction.ea).lower() in ["call", "jmp"]

def GetFunctionCallArguments(func_sig, xref_addr):
    """
    Given a function signature (func_sig) return the arguments of the
    function call at 'xref_addr'.
    """
    args = []

    # Get the corresponding basic block for the xref.
    bb = GetAddressBasicBlock(xref_addr)

    # Now obtain a list of all the instructions in said basic block.
    instructions = GetInstructions(bb.start_ea, bb.end_ea)

    # Remove instructions past the reference.
    instructions = filter(lambda x: x.ea <= xref_addr, instructions)

    # Check if we have a function call at the 'xref_addr'
    if not IsFunctionCall(instructions[-1]):
        raise RuntimeError("Cross reference is not a 'call', nor a 'jmp'.")

    # We've assumed that all the function's argument are set within one basic block.
    n_found_args = 0
    for ins in reversed(instructions[:-1]):
        if n_found_args == func_sig.nargs:
            break

        # Check if we have an instruction that sets the argument.
        if IsArgumentSetter(ins.ea):
            n_found_args += 1
            args.append(GetFunctionArgument(ins))

    return args

def GetFunctionDemangledName(xref_addr):
    """
    Return the demanlged name of a function at a given address 'xref_addr'.
    """
    tmp = GetFunctionName(xref_addr)
    name = Demangle(tmp, GetLongPrm(INF_SHORT_DN))
    return name if name else tmp

def IDAArgumentToSize(arg):
    """
    Try to convert an IDA 'argument' to an integer. If the argument is a
    register or a memory reference return -1 to place them last in the sorted list.    
    """
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
    """
    Sort by argument size.
    """
    arg = element.arguments[0].argument
    return IDAArgumentToSize(arg)

def print_references(func_name, func_nargs):
    # Declare the function signature with name and number of arguments.
    func_sig = FunctionSignature(func_name, func_nargs)

    interesting_functions = []

    # Get all the function names and match against the function name.
    for a in GetAllFunctionNames():
        if func_sig.name in a.name:
            interesting_functions.append(a)

    # Do the same for imports.
    for a in GetAllImportEntries():
        if func_sig.name in a.name:
            interesting_functions.append(a)

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

    # Sort by alloc size.
    results.sort(key=sort_func, reverse=True)
    for result in results:
        print "// Caller function %s " % result.caller_name
        print "// Call address    0x%.8x" % result.call_address
        print "// Alloc size      0x%.8x" % IDAArgumentToSize(result.arguments[0].argument)
        print "%s(%s);" % (result.callee_name, ",".join(map(lambda x: '"%s"' % x.argument, result.arguments)))
        print

if __name__ == "__main__":
    print_references("operator new", 1)
