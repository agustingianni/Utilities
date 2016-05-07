import idc
import idautils

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)
   
def handle_bp1():
    """
    Handler for the buffer append routine.

    .text:70F75BE0 push    edi                             ; size
    .text:70F75BE1 push    edx                             ; src
    .text:70F75BE2 push    eax                             ; dst
    .text:70F75BE3 call    _memcpy_0
    """
    size = GetRegValue("edi")
    src = GetRegValue("edx")
    dst = GetRegValue("eax")
    ip = GetRegValue("eip")

    print "memcpy(dst=0x%.8x, src=0x%.8x, size=0x%.8x)" % (dst, src, size)

    # Read the data
    data = GetManyBytes(src, size, use_dbg=True)
    if not data:
        print "Error reading src=0x%.8x" % (src)
        return
    
    hex_data = hexdump(data)

    print hex_data
    print
 
def install_bp1():
    bpaddr = 0x70F75BE3
    AddBpt(bpaddr)
    SetBptCnd(bpaddr, "handle_bp0()")

def handle_bp0():
    """
    .text:6FE414D2 mov     esi, [esp+44h+lpString1]
    .text:6FE414D6 mov     edi, [esp+44h+lp]
    """
    string_address = GetRegValue("esi")
    data = GetManyBytes(string_address, 32, use_dbg=True)
    if not data:
        print "Error reading src=0x%.8x" % (src)
        return
    
    hex_data = hexdump(data)
    
    print "Data @ 0x%.8x" % string_address
    print hex_data
    print

def install_bp0():
    bpaddr = 0x6FE414D6
    AddBpt(bpaddr)
    SetBptCnd(bpaddr, "handle_bp0()")

def handle_bp2():
    """
    .text:6FE30290 ; int __cdecl SHA1_sub_70F70290_calc(void *data)
    .text:6FE30290 SHA1_sub_70F70290_calc proc near        ; CODE XREF: SHA1_sub_70F703A0_get+32p
    .text:6FE30290                                         ; SHA1_sub_70F71350+4Dp ...
    .text:6FE30296 mov     ebp, [esp+44h+data]
    .text:6FE3029A push    edi
    .text:6FE3029B mov     edi, eax                        ; eax=strlen
    """
    data_address = GetRegValue("ebp")
    data_size = GetRegValue("eax")
    data = GetManyBytes(data_address, data_size, use_dbg=True)
    if not data:
        print "Error reading src=0x%.8x" % (src)
        return
    
    hex_data = hexdump(data)
    
    print "Data @ 0x%.8x" % data_address
    print hex_data
    print

def install_bp2():
    bpaddr = 0x6FE3029B
    AddBpt(bpaddr)
    SetBptCnd(bpaddr, "handle_bp0()")


def main():
    RunPlugin("python", 3)
    install_bp2()

if __name__ == '__main__':
    main()