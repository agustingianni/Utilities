def GetFunctionDemangledName(xref_addr):
	"""
	Return the demanlged name of a function at a given address 'xref_addr'.
	"""
	tmp = GetFunctionName(xref_addr)
	name = Demangle(tmp, GetLongPrm(INF_SHORT_DN))
	return name if name else tmp

ea = AskAddr(ScreenEA(), "Give me the address of what you want to propagate")
t = AskStr(GetType(ea), "Type for the data references")
t2 = AskStr(GetType(ea), "Type for the stub references")

if t[-1] != ';':
	t += ';'

if t2[-1] != ';':
	t2 += ';'

modified = set()

for data_ref in DataRefsTo(ea):
	if data_ref in modified:
		continue

	print "Setting type at 0x%.8x -> %s" % (data_ref, t)
	SetType(data_ref, t)
	modified.add(data_ref)

	names = set()
	# Now for each data reference check if there are code references.
	for code_ref in DataRefsTo(data_ref):
		if code_ref in modified or code_ref == data_ref:
			continue

		f = idaapi.get_func(code_ref)
		if not f:
			continue

		if f.startEA in modified:
			continue

		name = GetFunctionDemangledName(f.startEA)
		if "stub" in name.lower():
			# If the name of the code reference contains 'stub' then set also the type.
			print "Setting type at 0x%.8x : %s -> %s" % (f.startEA, name, t2)
			modified.add(f.startEA)
			SetType(f.startEA, t2)
