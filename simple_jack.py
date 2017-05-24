"""
Simple Jack symbol porting tool by goose (agustingianni@gmail.com).

This tool exists because for some reason diaphora does not assign
enough priority to "perfect" matches. The main idea is to get
as many symbols right so later on you can run diaphora and iterate.

The drill is simple, hash the bytes of all the functions in a db
and save them to a file. We will call this the 'primary' database.
Do the same for another DB (we call this the 'secondary' database)
and compare both. We only import identical matches and the only
info we import from the 'primary' is the function name.

This script has two modes:

    SCRIPT_MODE_DUMP:

        Used to create the primary and secondary database.
        You should run the script twice, first in the primary
        binary, which has your symbolicated binary, and second
        in the secondary binary, that is the one that will
        receive the information imported from the primary.

    SCRIPT_MODE_DIFF:

        Used once you've generated both the primary and secondary
        databases. It will read them both and perform the diffing.
        Once it finds matches, it will import the function name
        from the primary into the secondary.

        This mode is destructive, that is, it will change your
        IDB. Only run it if you are positive that you like the
        results.
"""

import pickle
import hashlib

import idaapi
from idc import *
from idaapi import *
from idautils import *

# Available modes, pick one.
SCRIPT_MODE_DUMP = 0
SCRIPT_MODE_DIFF = 1

# IMPORTANT: Manually set this to the mode you need, because fuck idapython.
CURRENT_SCRIPT_MODE = SCRIPT_MODE_DUMP

# Set this to true if you want to see some debugging output.
GLOBAL_DEBUG = False


def hash_bytes(bytes):
    return hashlib.md5(bytes).hexdigest()


def log(msg):
    Message("[%s] %s\n" % (time.asctime(), msg))


def load_db(db_name):
    db = None
    log("Loading DB from %s" % db_name)
    with open(db_name, 'rb') as input:
        db = pickle.load(input)

    return db


def save_db(db, db_name):
    log("Saving DB to %s" % db_name)
    with open(db_name, 'wb') as output:
        pickle.dump(db, output, pickle.HIGHEST_PROTOCOL)


def build_db():
    collision_keys = set()

    func_list = []
    segments = list(Segments())
    for seg_ea in segments:
        func_list.extend(list(Functions(seg_ea, SegEnd(seg_ea))))

    total_funcs = len(func_list)

    log("Total number of functions to export: %u" % total_funcs)

    functions_db = {}
    for f in func_list:
        # Get the function for this address.
        func = get_func(f)
        if not func:
            log("Cannot get a function object for 0x%x" % f)
            continue

        # Get the number of instructions.
        n_ins = 0
        flow = FlowChart(func)
        for block in flow:
            n_ins += len(list(Heads(block.startEA, block.endEA)))

        # Get the name of the function without demangling.
        name = GetFunctionName(f)

        # Calculate the size of the function.
        size = func.endEA - func.startEA

        # Do some sanity checks.
        assert (size == func.size()), "Invalid size."
        assert (func.startEA < func.endEA), "Invalid startEA / endEA values."

        # Get the hash of the function.
        ins_hash = hash_bytes(idc.GetManyBytes(func.startEA, size))

        # Check if we collide with another entry.
        if functions_db.has_key(ins_hash):
            log("Function @ 0x%.8x collides with function @ 0x%.8x" %
                (func.startEA, functions_db[ins_hash][2]))

            # Keep track of the collision.
            collision_keys.add(ins_hash)
            continue

        # Create an entry in the DB.
        functions_db[ins_hash] = (name, n_ins, func.startEA)

        if GLOBAL_DEBUG:
            log("Function name:%s start:0x%.8x end:0x%.8x size:%u n_ins:%u hash:%s" %
                (name, func.startEA, func.endEA, size, n_ins, ins_hash))

    # Delete the collision otherwise we may match functions incorrectly.
    for collision_key in collision_keys:
        del functions_db[collision_key]

    return functions_db


def do_diff():
    primary_db_path = AskFile(0, "primary.db", "Select the primary db file.")
    if primary_db_path is None:
        log("No file selected, exiting")
        return False

    secondary_db_path = AskFile(
        0, "secondary.db", "Select the secondary db file.")

    if secondary_db_path is None:
        log("No file selected, exiting")
        return False

    # Load the databases
    primary_db = load_db(primary_db_path)
    secondary_db = load_db(secondary_db_path)

    log("Diffing ...")

    # Proceed with the diffing.
    matches = 0
    for primary_hash, primary_val in primary_db.iteritems():
        # Check if 'primary_hash' from the primary is present in the secondary.
        if not secondary_db.has_key(primary_hash):
            continue

        # Hashes match.
        secondary_val = secondary_db[primary_hash]

        # Only match functions with a different name.
        if primary_val[0] == secondary_val[0]:
            continue

        function_ea = secondary_val[2]
        function_name_old = secondary_val[0]
        function_name_new = primary_val[0]

        # if GLOBAL_DEBUG:
        log("Function @ 0x%.8x -> From '%s' to '%s'" %
            (function_ea, function_name_old, function_name_new))

        # Set the secondary function name.
        if not MakeNameEx(function_ea, function_name_new, SN_NOWARN | SN_NOCHECK):
            log("Error setting function name to '%s'" % (function_name_new))

        matches += 1

    log("Number of matches: %u" % matches)


def do_save():
    db_path = AskFile(1, "*.db", "Select the file to store the db.")
    if db_path is None:
        log("No file selected, exiting")
        return False

    # Build the db for the current IDB.
    db = build_db()

    log("Number of entries in the DB: %u" % len(db))

    # Write the DB to disk.
    save_db(db, db_path)


if CURRENT_SCRIPT_MODE == SCRIPT_MODE_DUMP:
    do_save()

elif CURRENT_SCRIPT_MODE == SCRIPT_MODE_DIFF:
    do_diff()

else:
    log("Invalid script mode")
