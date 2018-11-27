# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

from __future__ import absolute_import, print_function, with_statement

from json import dumps
import socket
import sys

import ptvsd.comm.json
import ptvsd.comm.pydevd
import ptvsd.options
import ptvsd.session
import ptvsd.threading


class ConnectionError(Exception if sys.version_info < (3,) else ConnectionError):
    pass


# A dummy channel used when the client is not connected - just raises ConnectionError
# on all operations. The rest of the package can then handle lack of connection uniformly
# by trying to perform the operation and catching ConnectionError, regardless of whether
# the connection has not been established yet, or it has been closed.
class MissingJsonChannel(object):
    def send_event(self, event, body=None):
        raise ConnectionError


client = MissingJsonChannel()


def setup():
    ptvsd.comm.pydevd.connect_and_trace()
    ptvsd.session.start()
    return setup_client() if ptvsd.options.client else setup_server()


def setup_client():
    ptvsd.logging.info('Connecting to client at %r.', (ptvsd.options.host, ptvsd.options.port))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    client_socket.connect((ptvsd.options.host, ptvsd.options.port))
    setup_channel(client_socket)


def setup_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    server_socket.bind((ptvsd.options.host, ptvsd.options.port))
    server_socket.listen(1)

    def accept_worker():
        ptvsd.logging.info('Waiting for incoming client connection on %r.', server_socket.getsockname())
        client_socket, addr = server_socket.accept()
        ptvsd.logging.info('Incoming client connection accepted from %r.', addr)
        server_socket.close()
        setup_channel(client_socket)

    def on_shutdown():
        print('shutting down')
        server_socket.close()

    thread = ptvsd.threading.spawn('dap.accept', accept_worker, on_shutdown=on_shutdown)
    thread.start()


def setup_channel(client_socket):
    def request_handler(request):
        ptvsd.session.enqueue_client_request(request)
        return ptvsd.comm.json.Response.ASYNC

    global client

    stream = ptvsd.comm.json.JsonIOStream.from_socket(client_socket)
    if ptvsd.logging.is_logging:
        stream = LoggingJsonStream(stream, name='client')

    handlers = ptvsd.comm.json.MessageHandlers(request=request_handler)
    client = ptvsd.comm.json.JsonMessageChannel(stream, name='client', handlers=handlers)
    client.start()


class LoggingJsonStream(object):
    """Wraps a JsonStream, and logs all values passing through.
    """

    def __init__(self, stream, name):
        self.stream = stream
        self.name = name

    def close(self):
        self.stream.close()

    def read_json(self):
        value = self.stream.read_json()
        ptvsd.logging.debug('%s --> %s', self.name, dumps(value))
        return value

    def write_json(self, value):
        ptvsd.logging.debug('%s <-- %s', self.name, dumps(value))
        self.stream.write_json(value)
