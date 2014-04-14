"""
Utility to find all the strings inside an ill formed IDA Database.
The script does an exhaustive search of all the streams of ASCII characters
ending with a 0x00. Then we verify that the stream contains at least one
english word. If it does, then we define it as a string.

Coded by Agustin Gianni (agustin.gianni@gmail.com).
"""
import idaapi
import idc
import idautils
import string

try:
    import enchant
except ImportError:
    print "You need to install pyenchant to use method_1"

def is_printable(input_char):
    return input_char in string.printable

def method_1():
    """
    This method does not work very well so far.
    """
    dictionary = enchant.Dict("en_US")

    # Get the image base of the database.
    image_start = idc.MinEA()
    image_end = idc.MaxEA()
    image_size = image_end - image_start

    print "Analyzing image from %.8x-%.8x of size %.8x" % (image_start, image_end, image_size)

    cur_string = ""
    for cur_ea in xrange(image_start, image_end):
        byte_ = chr(Byte(cur_ea))
        if not is_printable(byte_):
            # If this is a terminating byte, check if the collected bytes form a string.
            if byte_ == '\x00' and len(cur_string):
                cur_string = cur_string.replace("-", " ").replace("_", " ")
                words = cur_string.split()

                nwords = 0
                for word in words:
                    if len(word) > 2 and dictionary.check(word) and (not word[0] in string.digits):
                        nwords += 1
                        if nwords > 1:
                            print "0x%.8x : %s" % (cur_ea, cur_string)
                            break
                
                cur_string = ""

        else:
            cur_string += byte_

def method_2():
    """
    Simple way to convert a table of strings into strings on IDA.
    """
    start = AskAddr(ScreenEA(), "Where do I start looking for strings?")
    end = idc.MaxEA()

    cur_string = ""
    last_byte = None
    for cur_ea in xrange(start, end):
        byte_ = chr(Byte(cur_ea))
        if not is_printable(byte_):
            # If this is a terminating byte, check if the collected bytes form a string.
            if byte_ == '\x00':
                if not len(cur_string):
                    print "Last string at 0x%.8x" % (cur_ea)
                    break

                else:
                    print "0x%.8x : %s" % (cur_ea - len(cur_string), cur_string)
                    MakeStr(cur_ea - len(cur_string), cur_ea + 1)
                    cur_string = ""
        else:
            cur_string += byte_

        last_byte = byte_

method_2()








