# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

from __future__ import absolute_import, print_function, with_statement

__all__ = ['fail_fast', 'fail_fast_exc', 'internal_thread']


import os
import threading
import xml.sax.saxutils


try:
    import urllib
    urllib.unquote
except Exception:
    import urllib.parse as urllib

import ptvsd.logging


def fail_fast(*args, **kwargs):
    try:
        raise Exception('Critical error')
    except Exception:
        fail_fast_exc(*args, **kwargs)


def fail_fast_exc(*args, **kwargs):
    ptvsd.logging.exception(*args, **kwargs)
    os._exit(1)


def internal_thread(name, target, **kwargs):
    """Return a thread that will be ignored by pydevd.
    """

    def thread_func(*args, **kwargs):
        try:
            target(*args, **kwargs)
        except:
            ptvsd.util.fail_fast_exc('Unhandled exception on background thread')

    t = threading.Thread(name='ptvsd.' + name, target=thread_func, **kwargs)
    t.daemon = True
    t.pydev_do_not_trace = True
    t.is_pydev_daemon_thread = True
    return t


def unquote(s):
    if s is None:
        return None
    return urllib.unquote(s)


def unquote_xml_path(s):
    """XML unescape after url unquote. This reverses the escapes and quotes done
    by pydevd.
    """
    if s is None:
        return None
    return xml.sax.saxutils.unescape(unquote(str(s)))
