for seg_ea in Segments():
    for head in Heads(seg_ea, SegEnd(seg_ea)):
        if isCode(GetFlags(head)):
            mnem = GetMnem(head)
            off = idaapi.get_offbase(head, 1)
            if mnem == "lea" and (not off in [0, -1, 0xffffffffffffffff, head, 0x5197d]):
                # Some of these are wrong, fix them
                if off in [0x5e98d, 0x6010d, 0x604ed, 0x61a9d, 0x63c7d, 0x671cd, 0x68afd, \
                            0x6a88d, 0x6c0ad, 0x6c60d, 0x6cacd, 0x6cf3d, 0x712ed, \
                            0x72c1d, 0x7450d, 0x753dd, 0x7643d, 0x78cbd, 0x78ffd, \
                            0x79a7d, 0x7a56d, 0x7b50d, 0x7dfed, 0x7eb0d, ]:
                    idaapi.set_offset(head, 1, head)

                print "%.8x %d %8x %s" % (head, GetOpType(head, 1), off, GetDisasm(head))
