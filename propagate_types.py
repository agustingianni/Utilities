ea = AskAddr(ScreenEA(), "Give me the address of what you want to propagate")
t = AskStr(GetType(ea), "Convert the default guessed type to whatever you want propagated")

if t[-1] != ';':
	t += ';'

for data_ref in DataRefsTo(ea):
	print "Setting type at 0x%.8x" % data_ref
	SetType(data_ref, t)
