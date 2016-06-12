Utilities
=========

Uncategorized utilities that do not need their own repository.


Instruction frequency counter (arm_frequency.py)
----------------------------------------------------

The script 'arm_frequency.py' takes as input the output of objdump 
on an ARM binary.
It will show the ammount of times every instruction was used, sorted
by the most used ones.

XRef printer (func_references.py)
---------------------------------

Small utility to print all the function calls to a given function.
This is generally used to look for calls to malloc like function.

DumpFunctionBytes.py
--------------------

IDA Python script that dumps the current function (you need to position
the cursor on the start of the function) as a shellcode.
It does a very limited analysis of the function in order to let you know
that you need to fix call sites to functions.

The main idea of this is being able to extract a function from a binary
and use it.
