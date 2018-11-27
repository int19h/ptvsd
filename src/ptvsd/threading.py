# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

from __future__ import absolute_import, print_function, unicode_literals, with_statement

# All background threads that are spawned in ptvsd MUST be spawned via this module!
#
# The first reason is that threads spawned here are rendered invisible to the debugger -
# they're not traced, reported in the list of threads etc.
#
# The second reason is thread lifetime management. All threads that are used by ptvsd
# must be daemon threads, so as to not prevent process shutdown when the main thread
# exits. However, on Python 2, there is a bug (https://bugs.python.org/issue14623) that
# affects daemon threads that are still running at shutdown - they cannot rely on any
# globals still being assigned, and that includes all globals exported from standard
# modules. In practice, this means that daemon threads are prone to spurious exceptions
# during shutdown. To enable clean shutdown, this module registers an atexit handler,
# and blocks process shutdown until all threads spawned from here exit properly - i.e.
# the non-daemon thread semantics is implemented manually on top of daemon threads).

__all__ = ['spawn']


import atexit
import threading

import ptvsd.util


threads = {}
lock = threading.Lock()


def spawn(name, target, on_shutdown):
    """Spawns an internal debugger thread.

    If on_shutdown is a false value, the thread is not supposed to be running when interpreter
    shuts down. If it is still running, this is treated as a fatal internal error.

    Otherwise, on_shutdown must be a callable object. In that case, this callback is invoked when
    interpreter starts shutting down (at the same stage when atexit.register callbacks are run),
    and must somehow notify the thread to terminate gracefully. After the callback is invoked,
    shutdown is blocked until the thread exits.
    """

    def thread_func(*args, **kwargs):
        try:
            target(*args, **kwargs)
        except:
            ptvsd.util.fail_fast_exc('Unhandled exception on background thread')
        with lock:
            del threads[t]

    name = 'ptvsd.' + name
    if threads is None:
        ptvsd.util.fail_fast_exc('Thread %r spawned during interpreter shutdown', name)

    t = threading.Thread(name=name, target=thread_func)
    t.daemon = True
    t.pydev_do_not_trace = True
    t.is_pydev_daemon_thread = True
    with lock:
        threads[t] = on_shutdown
    return t


@atexit.register
def wait_for_threads():
    global threads
    with lock:
        ts = threads
        threads = None
    for t, on_shutdown in ts.items():
        if t.is_alive:
            on_shutdown()
            t.join(1)
            if t.is_alive:
                ptvsd.util.fail_fast_exc('Thread %r did not terminate on shutdown', t.name)
