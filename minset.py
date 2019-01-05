"""
Tool to calculate the minimum set of files that have
approximatelly the best coverage.

The tool needs an input directory that contains the input
files which were used along with the trace files.
The name of the trace file must be <input_file>.log. This
way when we are processing the trace, we can refer to the
input file.

Example:

$ python minset.py -i /tmp/InputFiles -o /tmp/OutputFiles
Size of the universe: 6257
Current covered=0 new=4053
Current covered=4053 new=581
...
Original trace count: 1484
Min set trace count : 48

This will copy the input files that cover the most blocks
from the input directory into the output directory.
"""
import os
import re
import sys
import struct
import shutil
import argparse
from collections import namedtuple

TraceFile = namedtuple("TraceFile", [
    "path",
    "entries"
])

BasicBlock = namedtuple("BasicBlock", [
    "start",
    "size",
    "id"
])


def load_drcov_trace(filename):
    """
    A drcov trace file consists of a preamble with ascii data up to
    the start of the basic block table. The basic block table can be
    located by searching for the ascii header:

        'BB Table: <number> bbs'

    Following the header, the table consists of N structures:

        struct __attribute__((packed)) drcov_bb {
            uint32_t start;
            uint16_t size;
            uint16_t id;
        };    
    """
    trace = open(filename, "rb").read()
    match = re.search(r"BB Table:\s+(\d+)\s+bbs\n", trace)
    if not match:
        return TraceFile(filename, set())

    block_count = int(match.group(1))

    # An empty trace is possible so bail before tryint to process.
    if not block_count:
        return TraceFile(filename, set())

    # Size of a single basic block entry.
    entry_size = 8

    # Extract the basic block table.
    table = trace[match.end():]
    if len(table) != entry_size * block_count:
        print "The size of the table does not match the count of basic blocks."

    # Unpack the entries into a set to avoid repeats.
    entries = set()
    for i in range(0, block_count):
        block_offset = i * entry_size
        block_data = table[block_offset:block_offset+entry_size]
        start, size, id_ = struct.unpack("<LHH", block_data)
        entries.add(BasicBlock(start, size, id_))

    return TraceFile(filename, entries)


parser = argparse.ArgumentParser(description="Coverage Minimum Set")
parser.add_argument("-i", dest="input_dir")
parser.add_argument("-o", dest="output_dir")

args = parser.parse_args()
if not args.input_dir:
    print "No input directory supplied, use option -i to supply one."
    sys.exit(-1)

if not args.output_dir:
    print "No output directory supplied, use option -o to supply one."
    sys.exit(-1)

output_dir = os.path.abspath(args.output_dir)

# Get all trace files in the traces directory.
input_dir = os.path.abspath(args.input_dir)
traces_paths = filter(lambda fn: fn.endswith(".log"), os.listdir(input_dir))
traces_paths = map(lambda fn: os.path.join(input_dir, fn), traces_paths)

# Load the actual traces.
traces = map(load_drcov_trace, traces_paths)

# Implementation of https://en.wikipedia.org/wiki/Set_cover_problem#Greedy_algorithm.
universe = map(lambda x: x.entries, traces)
universe = set.union(*universe)

# Set of covered blocks.
covered = set()

# List with the actual files that create the min set.
min_set = []

print "Size of the universe: %u" % len(universe)

# Iterate until the 'covered' set equals the 'universe'.
while covered != universe:
    # Get the set that adds the most hits to the 'covered' set.
    subset = max(traces, key=lambda x: len(x.entries - covered))

    print "Current covered=%u new=%u" % (
        len(covered), len(subset.entries - covered))

    min_set.append(subset)
    covered |= subset.entries

print "Original trace count: %u" % len(traces)
print "Min set trace count : %u" % len(min_set)

# Get the input file name from the trace file and copy it to the output directory.
for trace in min_set:
    path = trace.path.replace(".log", "").replace("drcov.", "")
    shutil.copy(path, output_dir)
