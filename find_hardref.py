"""
Script to find hardcoded references inside an IDA database.
This is used to find pointers to stuff inside firmware like
Apple's iBoot.

Author: Agustin Gianni (agustingianni@gmail.com)
"""
import idaapi
import idc
import idautils
import struct

class HardReferencesChoose(Choose2):
    def __init__(self, title, refs):
        Choose2.__init__(self, title, [ ["Address", 10], ["Reference", 10], ["Address Text", 15], ["Reference Text", 15] ])
        self.n = 0
        
        self.items = []
        for ref in refs:
            address = ref[0]
            reference = ref[1]
            self.items += [self.make_item(address, reference, GetDisasm(address), GetDisasm(reference))]
        
        self.icon = 0
        self.selcount = 0
        self.deflt = -1
        self.popup_names = ["NOSE"]

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        idaapi.jumpto(self.items[n])

    def OnInsertLine(self):
        pass

    def OnSelectLine(self, n):
        self.selcount += 1
        idaapi.jumpto(int(self.items[n][0], 16))

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnRefresh(self, n):
        #print("refresh %d" % n)
        return n

    def OnGetIcon(self, n):
        if n % 2:
            return 10
        
        return 11

    def show(self):
        t = self.Show()
        if t < 0:
            return False
        return True

    def make_item(self, address, reference, addr_asm, ref_asm):        
        r = ["0x%08x" % address, "0x%08x" %  reference, addr_asm, ref_asm]
        self.n += 1
        return r

    def OnGetLineAttr(self, n):
        #if n % 2:
        #    return [0xF00000, 0]
        pass

def find_string_table_refs(string_table_start, string_table_end, mark=False):
    image_start = idc.MinEA()
    image_end = idc.MaxEA()
    image_size = image_end - image_start

    print "Analyzing image from %.8x-%.8x of size %.8x" % (image_start, image_end, image_size)

    for cur_ea in xrange(image_start, image_end, 4):
        cur_long = Dword(cur_ea)
        if cur_long >= string_table_start and cur_long < string_table_end:
            if mark:
                SetType(cur_ea, "char *ptr;")

            print "Found string table ref at 0x%.8x to 0x%.8x (%s)" % (cur_ea, cur_long, GetDisasm(cur_ea))

def find_any_refs(image_start, image_end, mark=False):
    image_size = image_end - image_start

    refs = []
    for cur_ea in xrange(image_start, image_end, 4):
        cur_long = Dword(cur_ea)
        if cur_long >= image_start and cur_long < image_end:
            if mark:
                MakeDword(cur_ea)

            print "Found hard ref at 0x%.8x to 0x%.8x (%s)" % (cur_ea, cur_long, GetDisasm(cur_ea))
            refs.append((cur_ea, cur_long))

    return refs

# Image limits
image_start = idc.MinEA()   
image_end = idc.MaxEA()

# Limits of the iBoot string table.
# string_table_start = 0x5FF345C0
# string_table_end = 0x5FF40ACD
# 
# find_string_table_refs(string_table_start, string_table_end, mark=True)
refs = find_any_refs(image_start, image_end, mark=False)
choose = HardReferencesChoose("Hard references", refs)
choose.show()