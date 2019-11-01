# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

from __future__ import absolute_import, division, print_function, unicode_literals

import platform
import pytest
import sys

from ptvsd.common import messaging
from tests import debug
from tests.debug import runners
from tests.patterns import some
from tests.timeline import Event, Request


# pytestmark = pytest.mark.skip("https://github.com/microsoft/ptvsd/issues/1706")


@pytest.mark.timeout(30)
@pytest.mark.parametrize(
    "start_method",
    [""]
    if sys.version_info < (3,)
    else ["spawn"]
    if platform.system() == "Windows"
    else ["spawn", "fork"],
)
def test_multiprocessing(pyfile, target, run, start_method):
    @pyfile
    def code_to_debug():
        import debug_me  # noqa
        import multiprocessing
        import os
        import sys

        def parent(q, a):
            from debug_me import backchannel

            print("spawning child")
            p = multiprocessing.Process(target=child, args=(q, a))
            p.start()
            print("child spawned")
            backchannel.send(p.pid)
            assert q.get() == "child", p.pid

            q.put("spawn!")
            grandchild_pid = a.get()
            backchannel.send(grandchild_pid)
            assert q.get() == "grandchild", grandchild_pid

            assert backchannel.receive() == "exit!"
            q.put("exit!")

            print("waiting for child")
            p.join()

        def child(q, a):
            print("entering child")
            a.put(("child", os.getpid()))

            assert q.get() == "spawn!"
            print("spawning grandchild")
            p = multiprocessing.Process(target=grandchild, args=(q, a))
            p.start()
            a.put(p.pid)

            print("waiting for grandchild")
            p.join()

            print("leaving child")

        def grandchild(q, a):
            print("entering grandchild")
            a.put(("grandchild", os.getpid()))

            assert q.get() == "exit!"
            print("leaving grandchild")

        if __name__ == "__main__":
            start_method = sys.argv[1]
            if start_method != "":
                multiprocessing.set_start_method(start_method)

            q = multiprocessing.Queue()
            a = multiprocessing.Queue()
            try:
                parent(q, a)
            finally:
                q.close()
                a.close()

    with debug.Session() as parent_session:
        parent_backchannel = parent_session.open_backchannel()

        with run(parent_session, target(code_to_debug, args=[start_method])):
            pass

        child_pid = parent_backchannel.receive()
        expected_child_config = dict(parent_session.config)
        expected_child_config.update(
            {
                "request": "attach",
                "subProcessId": child_pid,
                "host": some.str,
                "port": some.int,
            }
        )

        child_config = parent_session.wait_for_subprocess(child_pid)
        assert child_config == expected_child_config
        parent_session.proceed()

        with debug.Session(child_config) as child_session:
            with child_session.start():
                pass

            grandchild_pid = parent_backchannel.receive()
            expected_grandchild_config = dict(child_session.config)
            expected_grandchild_config.update(
                {
                    "request": "attach",
                    "subProcessId": grandchild_pid,
                    "host": some.str,
                    "port": some.int,
                }
            )

            grandchild_config = child_session.wait_for_subprocess(grandchild_pid)
            assert grandchild_config == expected_grandchild_config
            child_session.proceed()

            with debug.Session(grandchild_config) as grandchild_session:
                with grandchild_session.start():
                    pass
                parent_backchannel.send("exit!")


@pytest.mark.timeout(30)
@pytest.mark.skip("Needs refactoring to use the new debug.Session API")
@pytest.mark.parametrize(
    "start_method", [runners.launch, runners.attach_by_socket["cli"]]
)
def test_subprocess(pyfile, start_method, run_as):
    @pyfile
    def child():
        import sys
        from debug_me import backchannel

        backchannel.send(sys.argv)

    @pyfile
    def parent():
        import os
        import subprocess
        import sys
        import debug_me  # noqa

        argv = [sys.executable, sys.argv[1], "--arg1", "--arg2", "--arg3"]
        env = os.environ.copy()
        process = subprocess.Popen(
            argv,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        process.wait()

    with debug.Session(start_method, backchannel=True) as parent_session:
        parent_backchannel = parent_session.backchannel
        parent_session.configure(run_as, parent, subProcess=True, args=[child])
        parent_session.start_debugging()

        root_start_request, = parent_session.all_occurrences_of(
            Request("launch") | Request("attach")
        )
        root_process, = parent_session.all_occurrences_of(Event("process"))
        root_pid = int(root_process.body["systemProcessId"])

        child_subprocess = parent_session.wait_for_next(Event("ptvsd_subprocess"))
        assert child_subprocess == Event(
            "ptvsd_subprocess",
            {
                "rootProcessId": root_pid,
                "parentProcessId": root_pid,
                "processId": some.int,
                "port": some.int,
                "rootStartRequest": {
                    "seq": some.int,
                    "type": "request",
                    "command": root_start_request.command,
                    "arguments": root_start_request.arguments,
                },
            },
        )
        parent_session.proceed()

        with parent_session.attach_to_subprocess(child_subprocess) as child_session:
            child_session.start_debugging()

            child_argv = parent_backchannel.receive()
            assert child_argv == [child, "--arg1", "--arg2", "--arg3"]


@pytest.mark.timeout(30)
@pytest.mark.skip("Needs refactoring to use the new debug.Session API")
@pytest.mark.parametrize(
    "start_method", [runners.launch, runners.attach_by_socket["cli"]]
)
def test_autokill(pyfile, start_method, run_as):
    @pyfile
    def child():
        import debug_me  # noqa

        while True:
            pass

    @pyfile
    def parent():
        import os
        import subprocess
        import sys
        from debug_me import backchannel

        argv = [sys.executable, sys.argv[1]]
        env = os.environ.copy()
        subprocess.Popen(
            argv,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        backchannel.receive()

    with debug.Session(start_method, backchannel=True) as parent_session:
        parent_backchannel = parent_session.backchannel
        expected_exit_code = (
            some.int if parent_session.start_method.method == "launch" else 0
        )
        parent_session.expected_exit_code = expected_exit_code
        parent_session.configure(run_as, parent, subProcess=True, args=[child])
        parent_session.start_debugging()

        with parent_session.attach_to_next_subprocess() as child_session:
            child_session.start_debugging()

            if parent_session.start_method.method == "launch":
                # In launch scenario, terminate the parent process by disconnecting from it.
                try:
                    parent_session.request("disconnect")
                except messaging.NoMoreMessages:
                    # Can happen if ptvsd drops connection before sending the response.
                    pass
                parent_session.wait_for_disconnect()
            else:
                # In attach scenario, just let the parent process run to completion.
                parent_backchannel.send(None)


@pytest.mark.skip("Needs refactoring to use the new debug.Session API")
def test_argv_quoting(pyfile, start_method, run_as):
    @pyfile
    def args():
        import debug_me  # noqa

        args = [  # noqa
            r"regular",
            r"",
            r"with spaces" r'"quoted"',
            r'" quote at start',
            r'quote at end "',
            r'quote in " the middle',
            r'quotes "in the" middle',
            r"\path with\spaces",
            r"\path\with\terminal\backslash" + "\\",
            r"backslash \" before quote",
        ]

    @pyfile
    def parent():
        import debug_me  # noqa

        import sys
        import subprocess
        from args import args

        child = sys.argv[1]
        subprocess.check_call([sys.executable] + [child] + args)

    @pyfile
    def child():
        from debug_me import backchannel
        import sys

        from args import args as expected_args

        backchannel.send(expected_args)

        actual_args = sys.argv[1:]
        backchannel.send(actual_args)

    with debug.Session(start_method, backchannel=True) as session:
        backchannel = session.backchannel
        session.configure(run_as, parent, args=[child])

        session.start_debugging()

        expected_args = backchannel.receive()
        actual_args = backchannel.receive()
        assert expected_args == actual_args


@pytest.mark.skip("Needs refactoring to use the new debug.Session API")
def test_echo_and_shell(pyfile, run_as, start_method):
    """
    Checks https://github.com/microsoft/ptvsd/issues/1548
    """

    @pyfile
    def code_to_run():
        import debug_me  # noqa

        import sys
        import subprocess
        import os

        if sys.platform == "win32":
            args = ["dir", "-c", "."]
        else:
            args = ["ls", "-c", "-la"]

        p = subprocess.Popen(
            args,
            shell=True,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        stdout, _stderr = p.communicate()
        if sys.version_info[0] >= 3:
            stdout = stdout.decode("utf-8")

        if "code_to_run.py" not in stdout:
            raise AssertionError(
                'Did not find "code_to_run.py" when listing this dir with subprocess. Contents: %s'
                % (stdout,)
            )

    with debug.Session(start_method) as session:
        session.configure(run_as, code_to_run, subProcess=True)
        session.start_debugging()
