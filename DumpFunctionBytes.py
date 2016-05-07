"""
Script to dump the current function as a C/C++ shellcode blob.

Author: Agustin Gianni (agustingianni@gmail.com)
"""
fn_ea = ScreenEA()
f = idaapi.get_func(fn_ea)
start = f.startEA
size = f.endEA - start
contents = GetManyBytes(start, size)

print "Dumped [0x%.8x-0x%.8x]" % (start, start + size)

rem = len(contents) % 32
contents += "\xcc" * (32 - rem) if rem else ""

n_elements = len(contents) / 32
for i in range(0, len(contents), 32):
	print "\"%s\"" % "".join(["\\x%.2x" % ord(c) for c in contents[i : i + 32]])
