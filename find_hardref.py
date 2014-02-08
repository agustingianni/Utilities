"""
Script to find hardcoded references inside an IDA database.
This is used to find pointers to stuff inside firmware like
Apple's iBoot.

Coded by Agustin Gianni (agustin.gianni@gmail.com).
"""
import idaapi
import idc
import idautils
import struct

image_start = idc.MinEA()
image_end = idc.MaxEA()
image_size = image_end - image_start

print "Analyzing image from %.8x-%.8x of size %.8x" % (image_start, image_end, image_size)

for cur_ea in xrange(image_start, image_end):
	cur_long = Dword(cur_ea)
	if cur_long >= image_start and cur_long < image_end:
		print "Found hard ref at 0x%.8x to 0x%.8x" % (cur_ea, cur_long)
		MakeDword(cur_ea)