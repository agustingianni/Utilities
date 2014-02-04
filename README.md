Utilities
=========

Uncategorized utilities that do not need their own repository.


ARM instruction frequency counter (arm_frequency.py)
----------------------------------------------------

The script 'arm_frequency.py' takes as input the output of objdump 
on an ARM binary.
It will show the ammount of times every instruction was used, sorted
by the most used ones.

XRef printer (func_references.py)
---------------------------------

Small utility to print all the function calls to a given function.
This is generally used to look for calls to malloc like function.
