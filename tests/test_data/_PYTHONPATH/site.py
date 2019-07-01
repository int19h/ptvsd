# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

"""A dummy site.py that is automatically imported by Python on startup.

Imports debug_me to set up debugging automatically.
"""

# Since this effectively hijacks a standard Python module, the very first thing it
# needs to do is restore that standard module in its rightful place in sys.modules -
# otherwise things will break as soon as we try to import practically anything other
# than sys! Even from __future__ is not available at this point...

# Do it all inside a function, so that all imports etc are local - to avoid complex
# interactions with globals when modules get swapped.
def setup(this_file):
    import sys
    print('MODULES:', sys.modules)

    # Find all sys.path entries that would cause this module to load, instead of
    # the stdlib site module.
    prefixes = {p for p in sys.path if "test_data" in p and "_PYTHONPATH" in p}

    original_path = sys.path[:]
    try:
        # Remove those entries from sys.path.
        sys.path[:] = [p for p in sys.path if p not in prefixes]
        print(prefixes)
        print(original_path)
        print(sys.path)
        # Re-import site - this time from stdlib.
        del sys.modules["site"]
        import site
    finally:
        sys.path[:] = original_path

    assert site.__file__ != this_file

    # Now we can safely import other things.
    import __future__  # noqa
    import debug_me  # noqa

setup(__file__)
