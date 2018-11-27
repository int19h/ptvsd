# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

from __future__ import absolute_import, print_function, with_statement

__all__ = ['connect_and_trace', 'send_notification', 'send_request_and_get_response']


import itertools
import pydevd
import socket
import sys
import threading

from _pydevd_bundle import pydevd_comm
from _pydevd_bundle import pydevd_comm_constants

import ptvsd.logging
import ptvsd.util
import ptvsd.session


pydevd_socket = None
lock = threading.Lock()
seq_iter = itertools.count(1000000000)
handlers = {}
responses = {}
response_received = threading.Condition()


def connect_and_trace(**kwargs):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    server.bind(('127.0.0.1', 0))
    server.listen(1)

    def accept_worker():
        global pydevd_socket
        pydevd_socket, addr = server.accept()
        ptvsd.logging.info('Accepted incoming pydevd connection from %r.', addr)
        server.close()

        # When this connection is accepted, pydevd is inside settrace, and it will
        # not proceed until it receives CMD_RUN. We don't want settrace to block,
        # so we always issue CMD_RUN immediately as soon as pydevd connects. Note
        # that there's no waiting for response, since this is the thread that is
        # processing responses, and it therefore can't block on itself.
        send_request(pydevd_comm.CMD_RUN, '')
        socket_worker()

    thread = ptvsd.util.internal_thread('pydevd.socket', accept_worker)
    thread.start()

    host, port = server.getsockname()
    ptvsd.logging.info('Waiting for incoming pydevd connection on %r.', (host, port))

    pydevd.settrace(host=host, port=port, suspend=False, **kwargs)


def make_packet(cmd_id, args):
    with lock:
        seq = next(seq_iter)
    if ptvsd.logging.is_logging:
        cmd_name = pydevd_comm_constants.ID_TO_MEANING.get(str(cmd_id), cmd_id)
        ptvsd.logging.debug('pydevd <-- %s %s %s', cmd_name, seq, args)
    s = u'{}\t{}\t{}\n'.format(cmd_id, seq, args)
    return seq, s.encode('utf8')


def send_notification(cmd_id, args):
    assert pydevd_socket
    seq, data = make_packet(cmd_id, args)
    pydevd_socket.send(data)


def send_request(cmd_id, args):
    seq, data = make_packet(cmd_id, args)
    responses[seq] = None
    pydevd_socket.send(data)
    return seq


def send_request_and_get_response(cmd_id, args):
    with response_received:
        seq = send_request(cmd_id, args)
        while True:
            response_received.wait()
            if not responses:
                raise EOFError
            response = responses.pop(seq, None)
            if response is not None:
                return response


def socket_worker():
    socket_io = pydevd_socket.makefile('rwb', 0)
    while True:
        try:
            data = socket_io.readline()
        except Exception:
            data = None

        if not data:
            ptvsd.logging.info('pydevd closed connection.')
            with response_received:
                responses.clear()
            break

        if sys.version_info < (3,):
            data = ptvsd.util.unquote(data).decode('utf8')
        else:
            data = ptvsd.util.unquote(data.decode('utf8'))

        cmd_id, seq, args = data.split('\t', 2)
        seq = int(seq)

        if ptvsd.logging.is_logging:
            cmd_name = pydevd_comm_constants.ID_TO_MEANING.get(cmd_id, cmd_id)
            ptvsd.logging.debug('pydevd --> %s %s %s', cmd_name, seq, args.rstrip())

        with response_received:
            if seq in responses:
                responses[seq] = args
                response_received.notify_all()
                continue

        ptvsd.session.enqueue_pydevd_message(cmd_id, args)

