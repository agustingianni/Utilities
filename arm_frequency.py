"""
Small script to parse the output of arm-linux-androideabi-objdump
giving as a result the ammount of times a particular opname is used.

This was used to prioritize the implementation of the most used instructions
in an disassembler / emulator.

Agustin Gianni (agustingianni@gmail.com)
"""
import re
import sys
import operator
from collections import defaultdict

skip_list = ["cbnz", "svc", "lsls", "sbcs", "bics", "rscs", "movs", "muls", "mls", "teq", "adcs", "smmls", "vcls", "vmls"]
cond_codes = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"]
def drop_garbage(opname):
	if opname.startswith("it"):
		return "it"

	# Drop the wide specifier.
	t = opname[:-2] if (opname.endswith(".w") or opname.endswith(".n")) else opname

	# Some opcodes end with the leters of condition codes but have nothing to do with them.
	if t in skip_list:
		return t

	# Drop condition codes.
	for code in cond_codes:
		if t.endswith(code):
			t2 = t[:-2]
			if len(t2) <= 2 and not t2 in ["b", "bl", "bx"]:
				print "You need to add the following opname to the 'skip_list' %s" % t

			t = t2
			break

	# Remove the 'setsflags' indicator.
	if t[-1] == "s" and t not in ["cps", "mls", "mrs", "smmls", "srs", "subs", "vabs", "vcls", "vfms", "vmls", "vmrs", "vnmls", "qabs", "vrecps", "vrsqrts"]:
		return t[:-1]

	return t

# Match the opcode, opname and arguments of objdump's output for ARM.
regex_str = "\s*[0-9a-f]+\:\s+([0-9a-f]+\s+[0-9a-f]*)\s+([a-zA-Z.]+)\s+(.+)"
regex = re.compile(regex_str)

opname_freq = defaultdict(lambda: 0, {})

with open(sys.argv[1]) as f:
    for line in f:
        r = regex.search(line)
        if not r:
        	continue

        opcode, opname, args = r.groups()
        if opname.lower() in [".byte", ".word", ".dword", ".qword", ".short"]:
        	continue

        opname = drop_garbage(opname)

        opname_freq[opname] += 1


for el in sorted(opname_freq.iteritems(), key=operator.itemgetter(1), reverse=True):
	print "Instruction %10s is used %10d times" % el