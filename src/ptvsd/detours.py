# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

import os

# "force_pydevd" must be imported first to ensure (via side effects)
# that the ptvsd-vendored copy of pydevd gets used.
import ptvsd._vendored.force_pydevd # noqa

from _pydev_bundle import pydev_monkey
from _pydevd_bundle import pydevd_frame
from _pydevd_bundle import pydevd_extension_api
from _pydevd_bundle import pydevd_extension_utils

import ptvsd
import ptvsd.multiproc
import ptvsd.safe_repr


# See _vendored/pydevd/_pydev_bundle/pydev_monkey.py
def get_python_c_args(host, port, indC, args, setup):
    runner = '''
import sys
sys.path.append(r'{ptvsd_syspath}')
import ptvsd.multiproc
ptvsd.multiproc.init_subprocess(
    {initial_pid},
    {initial_request},
    {parent_pid},
    {parent_port},
    {first_port},
    {last_port},
    {pydevd_setup})
{rest}
'''

    first_port, last_port = ptvsd.multiproc.subprocess_port_range

    # __file__ will be .../ptvsd/__init__.py, and we want the ...
    ptvsd_syspath = os.path.join(ptvsd.__file__, '../..')

    return runner.format(
        initial_pid=ptvsd.multiproc.initial_pid,
        initial_request=ptvsd.multiproc.initial_request,
        parent_pid=os.getpid(),
        parent_port=ptvsd.multiproc.listener_port,
        first_port=first_port,
        last_port=last_port,
        ptvsd_syspath=ptvsd_syspath,
        pydevd_setup=setup,
        rest=args[indC + 1])


# See _vendored/pydevd/_pydevd_bundle/pydevd_frame.py
def file_tracing_filter(file_path):
    # Don't trace any ptvsd files.
    return file_path.startswith(ptvsd.PTVSD_DIR_PATH)


pydev_monkey.patch_args = ptvsd.multiproc.patch_and_quote_args
pydevd_frame.file_tracing_filter = file_tracing_filter


# Register our presentation provider as the first item on the list,
# so that we're in full control of presentation.
str_handlers = pydevd_extension_utils.EXTENSION_MANAGER_INSTANCE.type_to_instance.setdefault(pydevd_extension_api.StrPresentationProvider, [])
str_handlers.insert(0, ptvsd.safe_repr.SafeReprPresentationProvider.get())
