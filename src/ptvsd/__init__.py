# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

from __future__ import absolute_import, print_function, with_statement

__all__ = [
    '__version__', '__author__',
    'enable_attach', 'wait_for_attach', 'break_into_debugger', 'is_attached',
]

import os

PTVSD_DIR_PATH = os.path.dirname(os.path.abspath(__file__)) + os.path.sep
NORM_PTVSD_DIR_PATH = os.path.normcase(PTVSD_DIR_PATH)

# Load the vendored pydevd copy, and install our detours.
import ptvsd.detours # noqa
