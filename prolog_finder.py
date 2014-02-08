"""
Find potential ARM procedures prolog.

The idea is to detect all the common instructions used to build a function prolog, 
that is instructions like PUSH.

Coded by Agustin Gianni (agustin.gianni@gmail.com).

(0xfffffe00, 0x0000b400, eEncodingT1, eSize16)
(0xffffa000, 0xe92d0000, eEncodingT2, eSize32)
(0xffff0fff, 0xf84d0d04, eEncodingT3, eSize32)
(0x0fff0000, 0x092d0000, eEncodingA1, eSize32)
(0x0fff0fff, 0x052d0004, eEncodingA2, eSize32)
"""
import idaapi
import idc
import idautils
import struct

push_masks = [(0x0fff0000, 0x092d0000), (0x0fff0fff, 0x052d0004)]
def is_push(opcode):
	for mask in push_masks:
		if (mask[0] & opcode) == mask[1]:
			return True

	return False

image_start = idc.MinEA()
image_end = idc.MaxEA()
image_size = image_end - image_start

print "Analyzing image from %.8x-%.8x of size %.8x" % (image_start, image_end, image_size)

for cur_ea in xrange(image_start, image_end, 4):
	cur_long = Dword(cur_ea)
	if is_push(cur_long):
		print "Found candidate at 0x%.8x -> %s" % (cur_ea, GetDisasm(cur_ea))

