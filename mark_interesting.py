"""
Small idapython script that finds all the signed comparisions and marks
them with a color.
It will also find the sign extension instructions and it will also mark them.
"""

import idautils
import idc

from idaapi import *

def rgb_to_bgr(color):
    r = color >> 16
    g = color >> 8 & 0xff
    b = color & 0xff
    return (b << 16) | (g << 8) | r 

SIGNED_COLOR = rgb_to_bgr(0xFC8B8B)
INTERESTING_COLOR = rgb_to_bgr(0xFC8B8B)
UNSIGNED_COLOR = rgb_to_bgr(0x8BFCB5)
CALL_COLOR = rgb_to_bgr(0xC7F8FF)

signed_ins = ["JL", "JNGE", "JGE", "JNL", "JLE", "JNG", "JG", "JNLE"]
unsigned_ins = ["JB", "JNAE", "JC", "JNB", "JAE", "JNC", "JBE", "JNA", "JA", "JNBE"]
interesting_ins = ["MOVSX", "MOVSXD"]

def set_instruction_color(ea, color):
    idc.SetColor(ea, idc.CIC_ITEM, color)

def is_call(mnemonic):
    return mnemonic.upper() == "CALL"

def is_signed(mnemonic):
    return mnemonic.upper() in signed_ins

def is_unsigned(mnemonic):
    return mnemonic.upper() in unsigned_ins

def is_interesting(mnemonic):
    return mnemonic.upper() in interesting_ins

names = set()

i = 0
for seg_ea in Segments():
    for head in Heads(seg_ea, SegEnd(seg_ea)):
        i += 1

        if not isCode(GetFlags(head)):
            continue

        mnemonic = GetMnem(head)
        
        if is_unsigned(mnemonic):
            set_instruction_color(head, UNSIGNED_COLOR)
        
        elif is_signed(mnemonic):
            #print "Adding signed: 0x%.8x" % head
            set_instruction_color(head, SIGNED_COLOR)

        elif is_interesting(mnemonic):
            set_instruction_color(head, INTERESTING_COLOR)
            names.add(GetFunctionName(head))

        elif is_call(mnemonic):
            set_instruction_color(head, CALL_COLOR)

for name in names:
    print name