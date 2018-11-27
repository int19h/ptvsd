# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

from __future__ import absolute_import, print_function, with_statement

import io
import json
import os
import platform
import re
import site
import sys
import threading
import traceback

try:
    import queue
except ImportError:
    import Queue as queue

import pydevd_file_utils
from _pydevd_bundle import pydevd_comm
from _pydevd_bundle import pydevd_comm_constants

import ptvsd.comm
import ptvsd.multiproc
import ptvsd.pathutils
import ptvsd.safe_repr
import ptvsd.untangle
import ptvsd.util


WAIT_FOR_THREAD_FINISH_TIMEOUT = 1  # seconds

STEP_REASONS = {
        pydevd_comm.CMD_STEP_INTO,
        pydevd_comm.CMD_STEP_OVER,
        pydevd_comm.CMD_STEP_RETURN,
        pydevd_comm.CMD_STEP_INTO_MY_CODE,
}

EXCEPTION_REASONS = {
    pydevd_comm.CMD_STEP_CAUGHT_EXCEPTION,
    pydevd_comm.CMD_ADD_EXCEPTION_BREAK
}

# Completion types.
TYPE_IMPORT = '0'
TYPE_CLASS = '1'
TYPE_FUNCTION = '2'
TYPE_ATTR = '3'
TYPE_BUILTIN = '4'
TYPE_PARAM = '5'
TYPE_LOOK_UP = {
    TYPE_IMPORT: 'module',
    TYPE_CLASS: 'class',
    TYPE_FUNCTION: 'function',
    TYPE_ATTR: 'field',
    TYPE_BUILTIN: 'keyword',
    TYPE_PARAM: 'variable',
}


def is_debugger_internal_thread(thread_name):
    if thread_name:
        if thread_name.startswith('pydevd.'):
            return True
        elif thread_name.startswith('ptvsd.'):
            return True
    return False


# NOTE: Previously this included sys.prefix, sys.base_prefix and sys.real_prefix.
# On some systems those resolve to /usr. If user home is in /usr/home, then treating
# those as library paths will inadvertently include user code.
STDLIB_PATH_PREFIXES = []
if hasattr(site, 'getusersitepackages'):
    site_paths = site.getusersitepackages()
    if isinstance(site_paths, list):
        for site_path in site_paths:
            STDLIB_PATH_PREFIXES.append(os.path.normcase(site_path))
    else:
        STDLIB_PATH_PREFIXES.append(os.path.normcase(site_paths))

if hasattr(site, 'getsitepackages'):
    site_paths = site.getsitepackages()
    if isinstance(site_paths, list):
        for site_path in site_paths:
            STDLIB_PATH_PREFIXES.append(os.path.normcase(site_path))
    else:
        STDLIB_PATH_PREFIXES.append(os.path.normcase(site_paths))



class IDMap(object):
    """Maps VSCode entities to corresponding pydevd entities by ID.

    VSCode entity IDs are generated here when necessary.

    For VSCode, entity IDs are always integers, and uniquely identify
    the entity among all other entities of the same type - e.g. all
    frames across all threads have unique IDs.

    For pydevd, IDs can be integer or strings, and are usually specific
    to some scope - for example, a frame ID is only unique within a
    given thread. To produce a truly unique ID, the IDs of all the outer
    scopes have to be combined into a tuple. Thus, for example, a pydevd
    frame ID is (thread_id, frame_id).

    Variables (evaluation results) technically don't have IDs in pydevd,
    as it doesn't have evaluation persistence. However, for a given
    frame, any child can be identified by the path one needs to walk
    from the root of the frame to get to that child - and that path,
    represented as a sequence of its constituent components, is used by
    pydevd commands to identify the variable. So we use the tuple
    representation of the same as its pydevd ID.  For example, for
    something like foo[1].bar, its ID is:
      (thread_id, frame_id, 'FRAME', 'foo', 1, 'bar')

    For pydevd breakpoints, the ID has to be specified by the caller
    when creating, so we can just reuse the ID that was generated for
    VSC. However, when referencing the pydevd breakpoint later (e.g. to
    remove it), its ID must be specified together with path to file in
    which that breakpoint is set - i.e. pydevd treats those IDs as
    scoped to a file.  So, even though breakpoint IDs are unique across
    files, use (path, bp_id) as pydevd ID.
    """

    def __init__(self):
        self._vscode_to_pydevd = {}
        self._pydevd_to_vscode = {}
        self._next_id = 1
        self._lock = threading.Lock()

    def pairs(self):
        # TODO: docstring
        with self._lock:
            return list(self._pydevd_to_vscode.items())

    def add(self, pydevd_id):
        # TODO: docstring
        with self._lock:
            vscode_id = self._next_id
            if callable(pydevd_id):
                pydevd_id = pydevd_id(vscode_id)
            self._next_id += 1
            self._vscode_to_pydevd[vscode_id] = pydevd_id
            self._pydevd_to_vscode[pydevd_id] = vscode_id
        return vscode_id

    def remove(self, pydevd_id=None, vscode_id=None):
        # TODO: docstring
        with self._lock:
            if pydevd_id is None:
                pydevd_id = self._vscode_to_pydevd[vscode_id]
            elif vscode_id is None:
                vscode_id = self._pydevd_to_vscode[pydevd_id]
            del self._vscode_to_pydevd[vscode_id]
            del self._pydevd_to_vscode[pydevd_id]

    def to_pydevd(self, vscode_id):
        # TODO: docstring
        return self._vscode_to_pydevd[vscode_id]

    def to_vscode(self, pydevd_id, autogen):
        # TODO: docstring
        try:
            return self._pydevd_to_vscode[pydevd_id]
        except KeyError:
            if autogen:
                return self.add(pydevd_id)
            else:
                raise

    def pydevd_ids(self):
        # TODO: docstring
        with self._lock:
            ids = list(self._pydevd_to_vscode.keys())
        return ids

    def vscode_ids(self):
        # TODO: docstring
        with self._lock:
            ids = list(self._vscode_to_pydevd.keys())
        return ids



class ExceptionsManager(object):
    def __init__(self):
        self.exceptions = {}
        self.lock = threading.Lock()

    def remove_all_exception_breaks(self):
        with self.lock:
            for exception in self.exceptions.keys():
                ptvsd.comm.pydevd.send_notification(
                    pydevd_comm.CMD_REMOVE_EXCEPTION_BREAK,
                    'python-{}'.format(exception)
                )
            self.exceptions = {}

    def _find_exception(self, name):
        if name in self.exceptions:
            return name

        for ex_name in self.exceptions.keys():
            # exception name can be in repr form
            # here we attempt to find the exception as it
            # is saved in the dictionary
            if ex_name in name:
                return ex_name

        return 'BaseException'

    def get_break_mode(self, name):
        with self.lock:
            try:
                return self.exceptions[self._find_exception(name)]
            except KeyError:
                pass
        return 'unhandled'

    def add_exception_break(self, exception, break_raised, break_uncaught,
                            skip_stdlib=False):

        notify_on_handled_exceptions = 1 if break_raised else 0
        notify_on_unhandled_exceptions = 1 if break_uncaught else 0
        ignore_libraries = 1 if skip_stdlib else 0

        cmdargs = (
            exception,
            notify_on_handled_exceptions,
            notify_on_unhandled_exceptions,
            ignore_libraries,
        )
        break_mode = 'never'
        if break_raised:
            break_mode = 'always'
        elif break_uncaught:
            break_mode = 'unhandled'

        msg = 'python-{}\t{}\t{}\t{}'.format(*cmdargs)
        with self.lock:
            ptvsd.comm.pydevd.send_notification(pydevd_comm.CMD_ADD_EXCEPTION_BREAK, msg)
            self.exceptions[exception] = break_mode

    def apply_exception_options(self, exception_options, skip_stdlib=False):
        """
        Applies exception options after removing any existing exception
        breaks.
        """
        self.remove_all_exception_breaks()
        pyex_options = (opt
                        for opt in exception_options
                        if self._is_python_exception_category(opt))
        for option in pyex_options:
            exception_paths = option['path']
            if not exception_paths:
                continue

            mode = option['breakMode']
            break_raised = (mode == 'always')
            break_uncaught = (mode in ['unhandled', 'userUnhandled'])

            # Special case for the entire python exceptions category
            is_category = False
            if len(exception_paths) == 1:
                # TODO: isn't the first one always the category?
                if exception_paths[0]['names'][0] == 'Python Exceptions':
                    is_category = True
            if is_category:
                self.add_exception_break(
                    'BaseException', break_raised, break_uncaught, skip_stdlib)
            else:
                path_iterator = iter(exception_paths)
                # Skip the first one. It will always be the category
                # "Python Exceptions"
                next(path_iterator)
                exception_names = []
                for path in path_iterator:
                    for ex_name in path['names']:
                        exception_names.append(ex_name)
                for exception_name in exception_names:
                    self.add_exception_break(
                        exception_name, break_raised,
                        break_uncaught, skip_stdlib)

    def _is_python_exception_category(self, option):
        """
        Check if the option has entires and that the first entry
        is 'Python Exceptions'.
        """
        exception_paths = option['path']
        if not exception_paths:
            return False

        category = exception_paths[0]['names']
        if category is None or len(category) != 1:
            return False

        return category[0] == 'Python Exceptions'


class VariablesSorter(object):
    def __init__(self):
        self.variables = []  # variables that do not begin with underscores
        self.single_underscore = []  # variables beginning with underscores
        self.double_underscore = []  # variables beginning with two underscores
        self.dunder = []  # variables that begin & end with double underscores

    def append(self, var):
        var_name = var['name']
        if var_name.startswith('__'):
            if var_name.endswith('__'):
                self.dunder.append(var)
            else:
                self.double_underscore.append(var)
        elif var_name.startswith('_'):
            self.single_underscore.append(var)
        else:
            self.variables.append(var)

    def get_sorted_variables(self):
        def get_sort_key(o):
            return o['name']
        self.variables.sort(key=get_sort_key)
        self.single_underscore.sort(key=get_sort_key)
        self.double_underscore.sort(key=get_sort_key)
        self.dunder.sort(key=get_sort_key)
        return self.variables + self.single_underscore + self.double_underscore + self.dunder  # noqa


class ModulesManager(object):
    def __init__(self):
        self.module_id_to_details = {}
        self.path_to_module_id = {}
        self._lock = threading.Lock()
        self._next_id = 1

    def add_or_get_from_path(self, module_path):
        with self._lock:
            try:
                module_id = self.path_to_module_id[module_path]
                return self.module_id_to_details[module_id]
            except KeyError:
                pass

            search_path = self._get_platform_file_path(module_path)
            for _, value in list(sys.modules.items()):
                try:
                    path = self._get_platform_file_path(value.__file__)
                except AttributeError:
                    path = None

                if path and search_path == path:
                    module_id = self._next_id
                    self._next_id += 1

                    module = {
                        'id': module_id,
                        'package': value.__package__ if hasattr(value, '__package__') else None,
                        'path': module_path,
                    }

                    try:
                        module['name'] = value.__qualname__
                    except AttributeError:
                        module['name'] = value.__name__

                    try:
                        module['version'] = value.__version__
                    except AttributeError:
                        pass

                    self.path_to_module_id[module_path] = module_id
                    self.module_id_to_details[module_id] = module

                    ptvsd.comm.client.send_event('module', {
                        'reason': 'new',
                        'module': module
                    })
                    return module

        return None

    def _get_platform_file_path(self, path):
        if platform.system() == 'Windows':
            return path.lower()
        return path

    def get_all(self):
        with self._lock:
            return list(self.module_id_to_details.values())

    def check_unloaded_modules(self, module_event):
        pass


class InternalsFilter(object):
    """Identifies debugger internal artifacts.
    """
    # TODO: Move the internal thread identifier here

    def __init__(self):
        if platform.system() == 'Windows':
            self._init_windows()
        else:
            self._init_default()

    def _init_default(self):
        self._ignore_files = [
            '/ptvsd_launcher.py',
        ]

        self._ignore_path_prefixes = [
            os.path.dirname(os.path.abspath(__file__)),
        ]

    def _init_windows(self):
        self._init_default()
        files = []
        for f in self._ignore_files:
            files.append(f.lower())
        self._ignore_files = files

        prefixes = []
        for p in self._ignore_path_prefixes:
            prefixes.append(p.lower())
        self._ignore_path_prefixes = prefixes

    def is_internal_path(self, abs_file_path):
        # TODO: Remove replace('\\', '/') after the path mapping in pydevd
        # is fixed. Currently if the client is windows and server is linux
        # the path separators used are windows path separators for linux
        # source paths.
        is_windows = platform.system() == 'Windows'

        file_path = abs_file_path.lower() if is_windows else abs_file_path
        file_path = file_path.replace('\\', '/')
        for f in self._ignore_files:
            if file_path.endswith(f):
                return True
        for prefix in self._ignore_path_prefixes:
            prefix_path = prefix.replace('\\', '/')
            if file_path.startswith(prefix_path):
                return True
        return False


########################
# the debug config

def bool_parser(str):
    return str in ("True", "true", "1")


DEBUG_OPTIONS_PARSER = {
    'WAIT_ON_ABNORMAL_EXIT': bool_parser,
    'WAIT_ON_NORMAL_EXIT': bool_parser,
    'REDIRECT_OUTPUT': bool_parser,
    'VERSION': ptvsd.util.unquote,
    'INTERPRETER_OPTIONS': ptvsd.util.unquote,
    'WEB_BROWSER_URL': ptvsd.util.unquote,
    'DJANGO_DEBUG': bool_parser,
    'FLASK_DEBUG': bool_parser,
    'FIX_FILE_PATH_CASE': bool_parser,
    'CLIENT_OS_TYPE': ptvsd.util.unquote,
    'DEBUG_STDLIB': bool_parser,
    'STOP_ON_ENTRY': bool_parser,
    'SHOW_RETURN_VALUE': bool_parser,
    'MULTIPROCESS': bool_parser,
}


DEBUG_OPTIONS_BY_FLAG = {
    'RedirectOutput': 'REDIRECT_OUTPUT=True',
    'WaitOnNormalExit': 'WAIT_ON_NORMAL_EXIT=True',
    'WaitOnAbnormalExit': 'WAIT_ON_ABNORMAL_EXIT=True',
    'Django': 'DJANGO_DEBUG=True',
    'Flask': 'FLASK_DEBUG=True',
    'Jinja': 'FLASK_DEBUG=True',
    'FixFilePathCase': 'FIX_FILE_PATH_CASE=True',
    'DebugStdLib': 'DEBUG_STDLIB=True',
    'WindowsClient': 'CLIENT_OS_TYPE=WINDOWS',
    'UnixClient': 'CLIENT_OS_TYPE=UNIX',
    'StopOnEntry': 'STOP_ON_ENTRY=True',
    'ShowReturnValue': 'SHOW_RETURN_VALUE=True',
    'Multiprocess': 'MULTIPROCESS=True',
}


def extract_debug_options(opts, flags=None):
    """Return the debug options encoded in the given value.

    "opts" is a semicolon-separated string of "key=value" pairs.
    "flags" is a list of strings.

    If flags is provided then it is used as a fallback.

    The values come from the launch config:

     {
         type:'python',
         request:'launch'|'attach',
         name:'friendly name for debug config',
         debugOptions:[
             'RedirectOutput', 'Django'
         ],
         options:'REDIRECT_OUTPUT=True;DJANGO_DEBUG=True'
     }

    Further information can be found here:

     https://code.visualstudio.com/docs/editor/debugging#_launchjson-attributes
    """
    if not opts:
        opts = build_debug_options(flags)
    return parse_debug_options(opts)


def build_debug_options(flags):
    """Build string representation of debug options from the launch config."""
    return ';'.join(DEBUG_OPTIONS_BY_FLAG[flag]
                    for flag in flags or []
                    if flag in DEBUG_OPTIONS_BY_FLAG)


def parse_debug_options(opts):
    """Debug options are semicolon separated key=value pairs
        WAIT_ON_ABNORMAL_EXIT=True|False
        WAIT_ON_NORMAL_EXIT=True|False
        REDIRECT_OUTPUT=True|False
        VERSION=string
        INTERPRETER_OPTIONS=string
        WEB_BROWSER_URL=string url
        DJANGO_DEBUG=True|False
        CLIENT_OS_TYPE=WINDOWS|UNIX
        DEBUG_STDLIB=True|False
    """
    options = {}
    if not opts:
        return options

    for opt in opts.split(';'):
        try:
            key, value = opt.split('=')
        except ValueError:
            continue
        try:
            options[key] = DEBUG_OPTIONS_PARSER[key](value)
        except KeyError:
            continue

    if 'CLIENT_OS_TYPE' not in options:
        options['CLIENT_OS_TYPE'] = 'WINDOWS' if platform.system() == 'Windows' else 'UNIX' # noqa

    return options


INITIALIZE_RESPONSE = dict(
    supportsCompletionsRequest=True,
    supportsConditionalBreakpoints=True,
    supportsConfigurationDoneRequest=True,
    supportsDebuggerProperties=True,
    supportsEvaluateForHovers=True,
    supportsExceptionInfoRequest=True,
    supportsExceptionOptions=True,
    supportsHitConditionalBreakpoints=True,
    supportsLogPoints=True,
    supportsModulesRequest=True,
    supportsSetExpression=True,
    supportsSetVariable=True,
    supportsValueFormattingOptions=True,
    supportTerminateDebuggee=True,
    exceptionBreakpointFilters=[
        {
            'filter': 'raised',
            'label': 'Raised Exceptions',
            'default': False
        },
        {
            'filter': 'uncaught',
            'label': 'Uncaught Exceptions',
            'default': True
        },
    ],
)


def session_worker():
    try:
        while True:
            kind, message = message_queue.get()
            try:
                if kind is None:
                    break
                # elif kind == 'client_event':
                #     assert isinstance(message, ptvsd.comm.json.Event)
                #     getattr(DapHandlers, message.name + '_event')(message)
                elif kind == 'client_request':
                    assert isinstance(message, ptvsd.comm.json.Request)
                    handler = getattr(DapHandlers, message.command + '_request')
                    handler(message)
                    assert message.responded
                elif kind == 'pydevd_command':
                    cmd_id, args = message
                    handler_name = pydevd_comm_constants.ID_TO_MEANING[cmd_id]
                    handler = getattr(PydevdHandlers, handler_name)
                    handler(args)
                else:
                    ptvsd.util.fail_fast('Unknown message kind %r' % (kind,))
            except ptvsd.comm.ConnectionError:
                # The client can disconnect in the middle of the handler, in which case
                # any respond() or send_event() calls by the latter will fail with this
                # exception. Normally, we just want to ignore the handler in that case -
                # for those that need to do something special, they can catch and handle
                # ConnectionError themselves.
                ptvsd.logging.info('%r failed due to missing connection - ignoring.', handler)
    except Exception as ex:
        ptvsd.util.fail_fast_exc('Unhandled exception in %r', handler)


message_queue = queue.Queue()

def enqueue_pydevd_message(cmd_id, args):
    message_queue.put(('pydevd_command', (cmd_id, args)))

def enqueue_client_request(request):
    message_queue.put(('client_request', request))

def enqueue_client_event(event):
    message_queue.put(('client_event', event))


def start():
    ptvsd.logging.info('Starting debug session.')

    global message_loop_thread
    global client_id, start_reason, debug_options, config_done
    global thread_map, frame_map, var_map, bp_map, source_map
    global enable_source_references, path_mappings, path_casing
    global exceptions_mgr, modules_mgr, internals_filter

    message_loop_thread = ptvsd.util.internal_thread('message_loop', session_worker)
    message_loop_thread.start()

    client_id = None
    start_reason = None
    debug_options = {}
    config_done = False

    thread_map = IDMap()
    frame_map = IDMap()
    var_map = IDMap()
    bp_map = IDMap()
    source_map = IDMap()
    path_mappings = []
    path_casing = ptvsd.pathutils.PathUnNormcase()

    exceptions_mgr = ExceptionsManager()
    modules_mgr = ModulesManager()
    internals_filter = InternalsFilter()


def set_debug_options(args):
    global debug_options
    debug_options = extract_debug_options(
        args.get('options'),
        args.get('debugOptions'),
    )


def _wait_options():
    normal = debug_options.get('WAIT_ON_NORMAL_EXIT', False)
    abnormal = debug_options.get('WAIT_ON_ABNORMAL_EXIT', False)
    return normal, abnormal


def parse_xml_response(args):
    return ptvsd.untangle.parse(io.BytesIO(args.encode('utf8'))).xml


def send_cmd_version_command():
    cmd = pydevd_comm.CMD_VERSION
    default_os_type = 'WINDOWS' if platform.system() == 'Windows' else 'UNIX' # noqa
    client_os_type = debug_options.get('CLIENT_OS_TYPE', default_os_type)
    os_id = client_os_type
    msg = '1.1\t{}\tID'.format(os_id)
    ptvsd.comm.pydevd.send_request_and_get_response(cmd, msg)


def initialize_path_maps(args):
    global path_mappings
    path_mappings = []
    for pathMapping in args.get('pathMappings', []):
        localRoot = pathMapping.get('localRoot', '')
        remoteRoot = pathMapping.get('remoteRoot', '')
        if (len(localRoot) > 0 and len(remoteRoot) > 0):
            path_mappings.append((localRoot, remoteRoot))

    if len(path_mappings) > 0:
        pydevd_file_utils.setup_client_server_paths(path_mappings)


def process_debug_options():
    """Process the launch arguments to configure the debugger."""
    if debug_options.get('FIX_FILE_PATH_CASE', False):
        path_casing.enable()

    if debug_options.get('REDIRECT_OUTPUT', False):
        redirect_output = 'STDOUT\tSTDERR'
    else:
        redirect_output = ''
    ptvsd.comm.pydevd.send_request(pydevd_comm.CMD_REDIRECT_OUTPUT, redirect_output)

    if debug_options.get('STOP_ON_ENTRY', False) and start_reason == 'launch':
        ptvsd.comm.pydevd.send_request(pydevd_comm.CMD_STOP_ON_START, '1')

    if debug_options.get('SHOW_RETURN_VALUE', False):
        ptvsd.comm.pydevd.send_request(pydevd_comm.CMD_SHOW_RETURN_VALUES, '1\t1')

    if debug_options.get('MULTIPROCESS', False):
        if not ptvsd.options.multiprocess:
            ptvsd.options.multiprocess = True
            ptvsd.multiproc.listen_for_subprocesses()
            #start_subprocess_notifier()

    # Print on all but NameError, don't suspend on any.
    ptvsd.comm.pydevd.send_request(pydevd_comm.CMD_PYDEVD_JSON_CONFIG, json.dumps(dict(
        skip_suspend_on_breakpoint_exception=('BaseException',),
        skip_print_breakpoint_exception=('NameError',),
        multi_threads_single_notification=True,
    )))


def start_subprocess_notifier():
    global subprocess_notifier_thread
    subprocess_notifier_thread = ptvsd.util.internal_thread('subprocess_notifier', subprocess_notifier)
    subprocess_notifier_thread.start()


def subprocess_notifier():
    while not self.closed:
        try:
            subprocess_request, subprocess_response = ptvsd.multiproc.subprocess_queue.get(timeout=0.1)
        except queue.Empty:
            continue

        try:
            self.send_event('ptvsd_subprocess', **subprocess_request)
        except Exception:
            pass
        else:
            subprocess_response['incomingConnection'] = True

        ptvsd.multiproc.subprocess_queue.task_done()


def ensure_pydevd_commands_handled():
    # PyDevd guarantees that a response means all previous commands
    # have been handled.  (PyDevd handles messages sequentially.)
    # See GH-448.
    #
    # This is particularly useful for those commands that do not
    # have responses (e.g. CMD_SET_BREAK notification).
    return send_cmd_version_command()


def is_just_my_code_stepping_enabled():
    """Returns true if Just-My-Code stepping is enabled.

    Note: for now we consider DEBUG_STDLIB == False as JMC.
    """
    dbg_stdlib = debug_options.get('DEBUG_STDLIB', False)
    return not dbg_stdlib


def is_stdlib(filepath):
    filepath = os.path.normcase(os.path.normpath(filepath))
    for prefix in STDLIB_PATH_PREFIXES:
        if prefix != '' and filepath.startswith(prefix):
            return True
    return filepath.startswith(ptvsd.NORM_PTVSD_DIR_PATH)


def should_debug(filepath):
    return not (is_just_my_code_stepping_enabled() and is_stdlib(filepath))


def get_source_reference(filename):
    """Gets the source reference only in remote debugging scenarios.
    And we know that the path returned is the same as the server path
    (i.e. path has not been translated)"""

    if start_reason == 'launch':
        return 0

    # If we have no path mappings, then always enable source references.
    autogen = len(path_mappings) == 0

    try:
        return source_map.to_vscode(filename, autogen=autogen)
    except KeyError:
        pass

    # If file has been mapped, then source is available on client.
    for local_prefix, remote_prefix in path_mappings:
        if filename.startswith(local_prefix):
            return 0

    return source_map.to_vscode(filename, autogen=True)


def cleanup_frames_and_variables(pyd_tid, preserve_frames=()):
    """ Delete frames and variables for a given thread, except for the ones in preserve list.
    """
    for pyd_fid, vsc_fid in frame_map.pairs():
        if pyd_fid[0] == pyd_tid and pyd_fid[1] not in preserve_frames:
            frame_map.remove(pyd_fid, vsc_fid)

    for pyd_var, vsc_var in var_map.pairs():
        if pyd_var[0] == pyd_tid and pyd_fid[1] not in preserve_frames:
            var_map.remove(pyd_var, vsc_var)


def format_frame_name(fmt, name, module, line, path):
    frame_name = name
    if fmt.get('module', False):
        if module:
            if name == '<module>':
                frame_name = module['name']
            else:
                frame_name = '%s.%s' % (module['name'], name)
        else:
            _, tail = os.path.split(path)
            tail = tail[0:-3] if tail.lower().endswith('.py') else tail
            if name == '<module>':
                frame_name = '%s in %s' % (name, tail)
            else:
                frame_name = '%s.%s' % (tail, name)

    if fmt.get('line', False):
        frame_name = '%s : %d' % (frame_name, line)

    return frame_name


def has_raw_representation(var_type):
    return var_type in ('str', 'unicode', 'bytes', 'bytearray')


def get_variable_evaluate_name(pyd_var_parent, var_name):
    pyd_var_len = len(pyd_var_parent)
    if pyd_var_len > 3:
        # This means the current variable has a parent i.e, it is not a
        # FRAME variable. These require evaluateName to work in VS
        # watch window
        var = pyd_var_parent + (var_name,)
        eval_name = var[3]
        for s in var[4:]:
            try:
                # Check and get the dictionary key or list index.
                # Note: this is best effort, keys that are object
                # references will not work
                i = get_index_or_key(s)
                eval_name += '[{}]'.format(i)
            except Exception:
                eval_name += '.' + s
        return eval_name
    elif pyd_var_len == 3:
        return var_name
    else:
        return None


def get_index_or_key(text):
    # Dictionary resolver in pydevd provides key
    # in '<repr> (<hash>)' format
    result = re.match(r"(.*)\ \(([0-9]*)\)", text, re.IGNORECASE | re.UNICODE)
    if result and len(result.groups()) == 2:
        try:
            # check if group 2 is a hash
            int(result.group(2))
            return result.group(1)
        except Exception:
            pass
    # In the result XML from pydevd list indexes appear
    # as names. If the name is a number then it is a index.
    return int(text)


def get_hit_condition_expression(hit_condition):
    """Following hit condition values are supported

    * x or == x when breakpoint is hit x times
    * >= x when breakpoint is hit more than or equal to x times
    * % x when breakpoint is hit multiple of x times

    Returns '@HIT@ == x' where @HIT@ will be replaced by number of hits
    """
    if not hit_condition:
        return None

    expr = hit_condition.strip()
    try:
        int(expr)
        return '@HIT@ == {}'.format(expr)
    except ValueError:
        pass

    if expr.startswith('%'):
        return '@HIT@ {} == 0'.format(expr)

    if expr.startswith('==') or \
        expr.startswith('>') or \
        expr.startswith('<'):
        return '@HIT@ {}'.format(expr)

    return hit_condition


def get_bp_type(path):
    bp_type = 'python-line'
    if not path.lower().endswith('.py'):
        if debug_options.get('DJANGO_DEBUG', False):
            bp_type = 'django-line'
        elif debug_options.get('FLASK_DEBUG', False):
            bp_type = 'jinja2-line'
    return bp_type


def attach_or_launch_request(request):
    global start_reason
    ptvsd.multiproc.root_start_request = request
    start_reason = request.command
    set_debug_options(request.arguments)
    send_cmd_version_command()
    initialize_path_maps(request.arguments)
    request.respond()


def parse_exception_details(exc_xml, include_stack=True):
    xml = parse_xml_response(exc_xml)

    exc_source = None
    exc_stack = None
    exc_type = xml.thread['exc_type']
    exc_desc = xml.thread['exc_desc']

    try:
        exc_name = re.findall(r"[\'\"](.*)[\'\"]", exc_type)[0]
    except IndexError:
        exc_name = exc_type

    if include_stack:
        xframes = list(xml.thread.frame)
        frame_data = []
        for f in xframes:
            file_path = ptvsd.util.unquote_xml_path(f['file'])
            if internals_filter.is_internal_path(file_path) or not should_debug(file_path):
                continue

            line_no = int(f['line'])
            func_name = ptvsd.util.unquote(f['name'])
            if sys.version[:2] == (3, 4):
                # In 3.4.* format_list requires line_text component to be present.
                try:
                    with open(file_path, 'r') as f:
                        line_text = f.readlines()[line_no - 1]
                except Exception:
                    line_text = ''
                frame_data.append((file_path, line_no, func_name, line_text))
            else:
                frame_data.append((file_path, line_no, func_name, None))

        exc_stack = ''.join(traceback.format_list(frame_data))
        exc_source = ptvsd.util.unquote_xml_path(xframes[0]['file'])
        if internals_filter.is_internal_path(exc_source) or not should_debug(exc_source):
            exc_source = None

    return exc_name, exc_desc, exc_source, exc_stack


class DapHandlers(object):
    @staticmethod
    def initialize_request(request):
        global client_id
        client_id = request.arguments.get('clientID', None)
        ptvsd.comm.client.send_event('initialized')
        request.respond(INITIALIZE_RESPONSE)

    @staticmethod
    def attach_request(request):
        attach_or_launch_request(request)

    @staticmethod
    def launch_request(request):
        attach_or_launch_request(request)

    @staticmethod
    def configurationDone_request(request):
        global config_done
        process_debug_options()
        request.respond()
        ptvsd.comm.pydevd.send_request(pydevd_comm.CMD_RUN, '')
        ptvsd.comm.client.send_event('process', {
            'name': sys.argv[0],
            'systemProcessId': os.getpid(),
            'isLocalProcess': True,
            'startMethod': start_reason,
        })
        config_done = True

    @staticmethod
    def disconnect_request(request):
        request.respond()
        ptvsd.multiproc.kill_subprocesses()
        if start_reason == 'launch':
            os._exit(0)

    @staticmethod
    def threads_request(request):
        resp_args = ptvsd.comm.pydevd.send_request_and_get_response(pydevd_comm.CMD_LIST_THREADS, '')
        xml = parse_xml_response(resp_args)

        try:
            xthreads = xml.thread
        except AttributeError:
            xthreads = []

        threads = []
        for xthread in xthreads:
            try:
                name = ptvsd.util.unquote(xthread['name'])
            except KeyError:
                name = None
            if is_debugger_internal_thread(name):
                continue

            pyd_tid = xthread['id']
            try:
                vsc_tid = thread_map.to_vscode(pyd_tid, autogen=False)
            except KeyError:
                # This is a previously unseen thread
                vsc_tid = thread_map.to_vscode(pyd_tid, autogen=True)
                ptvsd.comm.client.send_event('thread', {
                    'reason': 'started',
                    'threadId': 'vsc_tid'
                })
            threads.append({'id': vsc_tid, 'name': name})

        request.respond({'threads': threads})

    @staticmethod
    def source_request(request):
        source_reference = request.arguments.get('sourceReference', 0)
        filename = '' if source_reference == 0 else source_map.to_pydevd(source_reference)

        if source_reference == 0:
            request.fail('Source unavailable')
        else:
            server_filename = pydevd_file_utils.norm_file_to_server(filename)
            cmd = pydevd_comm.CMD_LOAD_SOURCE
            content = ptvsd.comm.pydevd.send_request_and_get_response(cmd, server_filename)
            request.respond({'content': content})

    @staticmethod
    def stackTrace_request(request):
        vsc_tid = int(request.arguments['threadId'])
        startFrame = int(request.arguments.get('startFrame', 0))
        levels = int(request.arguments.get('levels', 0))
        fmt = request.arguments.get('format', {})

        try:
            pyd_tid = thread_map.to_pydevd(vsc_tid)
        except KeyError:
            # Unknown thread, nothing much we can do about it here
            return request.fail('Thread {} not found'.format(vsc_tid))

        resp_args = ptvsd.comm.pydevd.send_request_and_get_response(pydevd_comm.CMD_GET_THREAD_STACK, pyd_tid)
        xml = parse_xml_response(resp_args)
        xframes = list(xml.thread.frame)

        totalFrames = len(xframes)
        if levels == 0:
            levels = totalFrames

        stackFrames = []
        preserve_fids = []
        for xframe in xframes:
            if startFrame > 0:
                startFrame -= 1
                continue

            if levels <= 0:
                break
            levels -= 1

            pyd_fid = int(xframe['id'])
            preserve_fids.append(pyd_fid)
            key = (pyd_tid, pyd_fid)
            fid = frame_map.to_vscode(key, autogen=True)
            name = ptvsd.util.unquote(xframe['name'])
            # pydevd encodes if necessary and then uses urllib.quote.
            norm_path = path_casing.un_normcase(ptvsd.util.unquote_xml_path(xframe['file']))  # noqa
            source_reference = get_source_reference(norm_path)
            if not internals_filter.is_internal_path(norm_path):
                module = modules_mgr.add_or_get_from_path(norm_path)
            else:
                module = None
            line = int(xframe['line'])
            frame_name = format_frame_name(fmt, name, module, line, norm_path)

            stackFrames.append({
                'id': fid,
                'name': frame_name,
                'source': {
                    'path': norm_path,
                    'sourceReference': source_reference
                },
                'line': line, 'column': 1,
            })

        user_frames = []
        for frame in stackFrames:
            path = frame['source']['path']
            if not internals_filter.is_internal_path(path) and should_debug(path):
                user_frames.append(frame)

        cleanup_frames_and_variables(pyd_tid, preserve_fids)

        request.respond({
            'stackFrames': user_frames,
            'totalFrames': len(user_frames)
        })

    @staticmethod
    def scopes_request(request):
        vsc_fid = int(request.arguments['frameId'])
        pyd_tid, pyd_fid = frame_map.to_pydevd(vsc_fid)
        pyd_var = (pyd_tid, pyd_fid, 'FRAME')
        vsc_var = var_map.to_vscode(pyd_var, autogen=True)
        scope = {
            'name': 'Locals',
            'expensive': False,
            'variablesReference': vsc_var,
        }
        request.respond({'scopes': [scope]})

    @staticmethod
    def variables_request(request):
        vsc_var = int(request.arguments['variablesReference'])
        fmt = request.arguments.get('format', {})

        try:
            pyd_var = var_map.to_pydevd(vsc_var)
        except KeyError:
            return request.fail('Variable {} not found in frame'.format(vsc_var))

        if len(pyd_var) == 3:
            cmd = pydevd_comm.CMD_GET_FRAME
        else:
            cmd = pydevd_comm.CMD_GET_VARIABLE
        cmdargs = (str(s) for s in pyd_var)
        with (ptvsd.safe_repr.using_format(fmt)):
            resp_args = ptvsd.comm.pydevd.send_request_and_get_response(cmd, '\t'.join(cmdargs))

        xml = parse_xml_response(resp_args)
        try:
            xvars = xml.var
        except AttributeError:
            xvars = []

        variables = VariablesSorter()
        for xvar in xvars:
            attributes = []
            var_name = ptvsd.util.unquote(xvar['name'])
            var_type = ptvsd.util.unquote(xvar['type'])
            var_value = ptvsd.util.unquote(xvar['value'])
            var = {
                'name': var_name,
                'type': var_type,
                'value': var_value,
            }

            if has_raw_representation(var_type):
                attributes.append('rawString')

            if bool(xvar['isRetVal']):
                attributes.append('readOnly')
                var['name'] = '(return) %s' % var_name
            else:
                if bool(xvar['isContainer']):
                    pyd_child = pyd_var + (var_name,)
                    var['variablesReference'] = var_map.to_vscode(
                        pyd_child, autogen=True)

                eval_name = get_variable_evaluate_name(pyd_var, var_name)
                if eval_name:
                    var['evaluateName'] = eval_name

            if len(attributes) > 0:
                var['presentationHint'] = {'attributes': attributes}

            variables.append(var)

        request.respond({
            'variables': variables.get_sorted_variables()
        })

    @staticmethod
    def setVariable_request(request):
        var_name = request.arguments['name']
        var_value = request.arguments['value']
        vsc_var = int(request.arguments['variablesReference'])
        fmt = request.arguments.get('format', {})

        if var_name.startswith('(return) '):
            return request.fail('Cannot change return value')

        try:
            pyd_var = var_map.to_pydevd(vsc_var)
        except KeyError:
            return request.fail('Variable {} not found in frame'.format(vsc_var))

        lhs_expr = get_variable_evaluate_name(pyd_var, var_name)
        if not lhs_expr:
            lhs_expr = var_name
        expr = '%s = %s' % (lhs_expr, var_value)
        # pydevd message format doesn't permit tabs in expressions
        expr = expr.replace('\t', ' ')

        pyd_tid = str(pyd_var[0])
        pyd_fid = str(pyd_var[1])

        # VSC gives us variablesReference to the parent of the variable
        # being set, and variable name; but pydevd wants the ID
        # (or rather path) of the variable itself.
        pyd_var += (var_name,)
        vsc_var = var_map.to_vscode(pyd_var, autogen=True)

        cmd_args = [pyd_tid, pyd_fid, 'LOCAL', expr, '1']
        with ptvsd.safe_repr.using_format(fmt):
            ptvsd.comm.pydevd.send_request_and_get_response(
                pydevd_comm.CMD_EXEC_EXPRESSION,
                '\t'.join(cmd_args))

        cmd_args = [pyd_tid, pyd_fid, 'LOCAL', lhs_expr, '1']
        with ptvsd.safe_repr.using_format(fmt):
            resp_args = ptvsd.comm.pydevd.send_request_and_get_response(
                pydevd_comm.CMD_EVALUATE_EXPRESSION,
                '\t'.join(cmd_args))

        xml = parse_xml_response(resp_args)
        xvar = xml.var

        response = {
            'type': ptvsd.util.unquote(xvar['type']),
            'value': ptvsd.util.unquote(xvar['value']),
        }
        if bool(xvar['isContainer']):
            response['variablesReference'] = vsc_var
        request.respond(response)

    @staticmethod
    def evaluate_request(request):
        # pydevd message format doesn't permit tabs in expressions
        expr = request.arguments['expression'].replace('\n', '@LINE@').replace('\t', ' ')
        fmt = request.arguments.get('format', {})

        vsc_fid = int(request.arguments['frameId'])
        pyd_tid, pyd_fid = frame_map.to_pydevd(vsc_fid)

        cmd_args = (pyd_tid, pyd_fid, 'LOCAL', expr, '1')
        msg = '\t'.join(str(s) for s in cmd_args)
        with ptvsd.safe_repr.using_format(fmt):
            resp_args = ptvsd.comm.pydevd.send_request_and_get_response(
                pydevd_comm.CMD_EVALUATE_EXPRESSION, msg)

        xml = parse_xml_response(resp_args)
        xvar = xml.var

        context = request.arguments.get('context', '')
        is_eval_error = xvar['isErrorOnEval'] == 'True'
        if context == 'hover' and is_eval_error:
            return request.respond({
                'result': None,
                'variablesReference': 0
            })

        if context == 'repl' and is_eval_error:
            # try exec for repl requests
            with ptvsd.safe_repr.using_format(fmt):
                resp_args = ptvsd.comm.pydevd.send_request_and_get_response(
                    pydevd_comm.CMD_EXEC_EXPRESSION, msg)
            try:
                xml = parse_xml_response(resp_args)
            except Exception:
                # if resp_args is not xml then it contains the error traceback
                pass
            else:
                xvar = xml.var
            result_type = ptvsd.util.unquote(xvar['type'])
            result = ptvsd.util.unquote(xvar['value'])
            return request.respond({
                'result': None if result == 'None' and result_type == 'NoneType' else result,
                'type': result_type,
                'variablesReference': 0,
            })

        pyd_var = (pyd_tid, pyd_fid, 'EXPRESSION', expr)
        vsc_var = var_map.to_vscode(pyd_var, autogen=True)
        var_type = ptvsd.util.unquote(xvar['type'])
        var_value = ptvsd.util.unquote(xvar['value'])
        response = {
            'type': var_type,
            'result': var_value,
        }

        if has_raw_representation(var_type):
            response['presentationHint'] = {'attributes': ['rawString']}

        if bool(xvar['isContainer']):
            response['variablesReference'] = vsc_var

        request.respond(response)

    @staticmethod
    def setExpression_request(request):
        # TODO: docstring

        vsc_fid = int(request.arguments['frameId'])
        pyd_tid, pyd_fid = frame_map.to_pydevd(vsc_fid)
        fmt = request.arguments.get('format', {})

        lhs_expr = request.arguments.get('expression')
        rhs_expr = request.arguments.get('value')
        expr = '%s = (%s)' % (lhs_expr, rhs_expr)

        # pydevd message format doesn't permit tabs in expressions
        expr = expr.replace('\t', ' ')

        cmd_args = (pyd_tid, pyd_fid, 'LOCAL', expr, '1')
        msg = '\t'.join(str(s) for s in cmd_args)
        with ptvsd.safe_repr.using_format(fmt):
            ptvsd.comm.pydevd_send_request_and_get_response(
                pydevd_comm.CMD_EXEC_EXPRESSION, msg)

        # Return nothing - the client will call getVariables to retrieve the
        # updated values anyway. Doing eval on the left-hand-side expression
        # may have side-effects
        request.respond()

    @staticmethod
    def modules_request(request):
        modules = list(modules_mgr.get_all())
        user_modules = []
        for module in modules:
            if not internals_filter.is_internal_path(module['path']):
                user_modules.append(module)
        request.respond({
            'modules': user_modules,
            'totalModules': len(user_modules)
        })

    @staticmethod
    def pause_request(request):
        if not config_done:
            return request.fail('"pause" request cannot precede "configurationDone" response')
        ptvsd.comm.pydevd.send_notification(pydevd_comm.CMD_THREAD_SUSPEND, '*')
        request.respond()

    @staticmethod
    def continue_request(request):
        ptvsd.comm.pydevd.send_notification(pydevd_comm.CMD_THREAD_RUN, '*')
        request.respond({'allThreadsContinued': True})

    @staticmethod
    def next_request(request):
        tid = thread_map.to_pydevd(int(request.arguments['threadId']))
        ptvsd.comm.pydevd.send_notification(pydevd_comm.CMD_STEP_OVER, tid)
        request.respond()

    @staticmethod
    def stepIn_request(request):
        tid = thread_map.to_pydevd(int(request.arguments['threadId']))
        if is_just_my_code_stepping_enabled():
            ptvsd.comm.pydevd.send_notification(pydevd_comm.CMD_STEP_INTO_MY_CODE, tid)
        else:
            ptvsd.comm.pydevd.send_notification(pydevd_comm.CMD_STEP_INTO, tid)
        request.respond()

    @staticmethod
    def stepOut_request(request):
        tid = thread_map.to_pydevd(int(request.arguments['threadId']))
        ptvsd.comm.pydevd.send_notification.pydevd_notify(pydevd_comm.CMD_STEP_RETURN, tid)
        request.respond()

    @staticmethod
    def setBreakpoints_request(request):
        bps = []
        path = request.arguments['source']['path']
        path_casing.track_file_path_case(path)
        src_bps = request.arguments.get('breakpoints', [])

        bp_type = get_bp_type(path)

        # First, we must delete all existing breakpoints in that source.
        cmd = pydevd_comm.CMD_REMOVE_BREAK
        for pyd_bpid, vsc_bpid in bp_map.pairs():
            if pyd_bpid[0] == path:
                msg = '{}\t{}\t{}'.format(bp_type, path, vsc_bpid)
                ptvsd.comm.pydevd.send_notification(cmd, msg)
                bp_map.remove(pyd_bpid, vsc_bpid)

        cmd = pydevd_comm.CMD_SET_BREAK
        msgfmt = u'{}\t{}\t{}\t{}\tNone\t{}\t{}\t{}\t{}\tALL'

        for src_bp in src_bps:
            line = src_bp['line']
            vsc_bpid = bp_map.add(lambda vsc_bpid: (path, vsc_bpid))
            path_casing.track_file_path_case(path)

            condition = src_bp.get('condition', None)
            hit_condition = get_hit_condition_expression(src_bp.get('hitCondition', None))
            log_message = src_bp.get('logMessage', '')
            if len(log_message) == 0:
                is_logpoint = None
                expression = None
            else:
                is_logpoint = True
                expressions = re.findall(r'\{.*?\}', log_message)
                if len(expressions) == 0:
                    expression = '{}'.format(repr(log_message))
                else:
                    raw_text = ptvsd.util.reduce(lambda a, b: a.replace(b, '{}'), expressions, log_message)
                    raw_text = raw_text.replace('"', '\\"')
                    expression_list = ', '.join([s.strip('{').strip('}').strip() for s in expressions])
                    expression = '"{}".format({})'.format(raw_text, expression_list)

            ptvsd.comm.pydevd.send_notification(cmd, msgfmt.format(
                vsc_bpid, bp_type, path, line, condition,
                expression, hit_condition, is_logpoint
            ))
            bps.append({
                'id': vsc_bpid,
                'verified': True,
                'line': line,
            })

        ensure_pydevd_commands_handled()
        request.respond({'breakpoints': bps})

    @staticmethod
    def setExceptionBreakpoints_request(request):
        filters = request.arguments['filters']
        exception_options = request.arguments.get('exceptionOptions', [])
        jmc = is_just_my_code_stepping_enabled()

        if exception_options:
            exceptions_mgr.apply_exception_options(exception_options, jmc)
        else:
            exceptions_mgr.remove_all_exception_breaks()
            break_raised = 'raised' in filters
            break_uncaught = 'uncaught' in filters
            if break_raised or break_uncaught:
                exceptions_mgr.add_exception_break(
                    'BaseException', break_raised, break_uncaught,
                    skip_stdlib=jmc)

        request.respond()

    @staticmethod
    def exceptionInfo_request(request):
        pyd_tid = thread_map.to_pydevd(request.arguments['threadId'])

        resp_args = ptvsd.comm.pydevd.send_request_and_get_response(pydevd_comm.CMD_GET_EXCEPTION_DETAILS, pyd_tid)
        name, description, source, stack  = parse_exception_details(resp_args)

        request.respond({
            'exceptionId': name,
            'description': description,
            'breakMode': exceptions_mgr.get_break_mode(name),
            'details': {
                'typeName': name,
                'message': description,
                'stackTrace': stack,
                'source': source
            },
        })

    @staticmethod
    def completions_request(request):
        text = request.arguments['text']
        vsc_fid = request.arguments.get('frameId', None)

        try:
            pyd_tid, pyd_fid = frame_map.to_pydevd(vsc_fid)
        except KeyError:
            return request.fail('Frame {} not found'.format(vsc_fid))

        cmd_args = '{}\t{}\t{}\t{}'.format(pyd_tid, pyd_fid, 'LOCAL', text)
        resp_args = ptvsd.comm.pydevd.send_request_and_get_response(pydevd_comm.CMD_GET_COMPLETIONS, cmd_args)

        xml = parse_xml_response(resp_args)
        targets = []
        for item in list(getattr(xml, 'comp', [])):
            target = {}
            target['label'] = ptvsd.util.unquote(item['p0'])
            try:
                target['type'] = TYPE_LOOK_UP[item['p3']]
            except KeyError:
                pass
            targets.append(target)

        request.respond({'targets': targets})

    @staticmethod
    def ptvsd_systemInfo_request(request):
        try:
            pid = os.getpid()
        except AttributeError:
            pid = None

        try:
            impl_desc = platform.python_implementation()
        except AttributeError:
            try:
                impl_desc = sys.implementation.name
            except AttributeError:
                impl_desc = None

        def version_str(v):
            return '{}.{}.{}{}{}'.format(
                v.major,
                v.minor,
                v.micro,
                v.releaselevel,
                v.serial)

        try:
            impl_name = sys.implementation.name
        except AttributeError:
            impl_name = None

        try:
            impl_version = version_str(sys.implementation.version)
        except AttributeError:
            impl_version = None

        request.respond({
            'ptvsd': {
                'version': ptvsd.__version__,
            },
            'python': {
                'version': version_str(sys.version_info),
                'implementation': {
                    'name': impl_name,
                    'version': impl_version,
                    'description': impl_desc,
                },
            },
            'platform': {
                'name': sys.platform,
            },
            'process': {
                'pid': pid,
                'executable': sys.executable,
                'bitness': 64 if sys.maxsize > 2**32 else 32,
            },
        })

    @staticmethod
    def on_setDebuggerProperty(request):
        if 'JustMyCodeStepping' in request.arguments:
            debug_options['DEBUG_STDLIB'] = int(request.arguments['JustMyCodeStepping']) > 0
        request.respond()


class PydevdHandlers(object):
    @staticmethod
    def CMD_INPUT_REQUESTED(args):
        '''
        no-op: if stdin is requested, right now the user is expected to enter
        text in the terminal and the debug adapter doesn't really do anything
        (although in the future it could see that stdin is being requested and
        redirect any evaluation request to stdin).
        '''

    @staticmethod
    def CMD_THREAD_CREATE(args):

        xml = parse_xml_response(args)
        try:
            name = ptvsd.util.unquote(xml.thread['name'])
        except KeyError:
            name = None

        if not is_debugger_internal_thread(name):
            pyd_tid = xml.thread['id']
            # Any internal pydevd or ptvsd threads will be ignored
            # everywhere
            try:
                thread_map.to_vscode(pyd_tid, autogen=False)
            except KeyError:
                tid = thread_map.to_vscode(pyd_tid, autogen=True)
                ptvsd.comm.client.send_event('thread', {
                    'reason': 'started',
                    'threadId': tid
                })

    @staticmethod
    def CMD_THREAD_KILL(args):
        pyd_tid = args.strip()

        # All frames, and variables for
        # this thread are now invalid; clear their IDs.
        for pyd_fid, vsc_fid in frame_map.pairs():
            if pyd_fid[0] == pyd_tid:
                frame_map.remove(pyd_fid, vsc_fid)

        for pyd_var, vsc_var in var_map.pairs():
            if pyd_var[0] == pyd_tid:
                var_map.remove(pyd_var, vsc_var)

        try:
            vsc_tid = thread_map.to_vscode(pyd_tid, autogen=False)
        except KeyError:
            pass
        else:
            thread_map.remove(pyd_tid, vsc_tid)
            ptvsd.comm.client.send_event('thread', {
                'reason': 'exited',
                'threadId': vsc_tid
            })

    @staticmethod
    def CMD_THREAD_SUSPEND(args):
        xml = parse_xml_response(args)
        pyd_tid = xml.thread['id']
        reason = int(xml.thread['stop_reason'])

        # This is needed till https://github.com/Microsoft/ptvsd/issues/477
        # is done. Remove this after adding the appropriate pydevd commands to
        # do step over and step out
        xframes = list(xml.thread.frame)
        xframe = xframes[0]
        filepath = ptvsd.util.unquote_xml_path(xframe['file'])
        if reason in STEP_REASONS or reason in EXCEPTION_REASONS:
            if internals_filter.is_internal_path(filepath) or not should_debug(filepath):
                ptvsd.comm.pydev.send_notification(pydevd_comm.CMD_THREAD_RUN, pyd_tid)
                return

    @staticmethod
    def CMD_THREAD_SUSPEND_SINGLE_NOTIFICATION(args):
        # NOTE: We should add the thread to VSC thread map only if the
        # thread is seen here for the first time in 'attach' scenario.
        # If we are here in 'launch' scenario and we get KeyError then
        # there is an issue in reporting of thread creation.
        suspend_info = json.loads(args)
        pyd_tid = suspend_info['thread_id']
        reason = suspend_info['stop_reason']
        autogen = start_reason == 'attach'
        vsc_tid = thread_map.to_vscode(pyd_tid, autogen=autogen)

        exc_desc = None
        exc_name = None

        if reason in STEP_REASONS:
            reason = 'step'
        elif reason in EXCEPTION_REASONS:
            reason = 'exception'
        elif reason == pydevd_comm.CMD_SET_BREAK:
            reason = 'breakpoint'
        else:
            reason = 'pause'

        if reason == 'exception':
            cmdid = pydevd_comm.CMD_GET_EXCEPTION_DETAILS
            resp_args = ptvsd.comm.pydevd.send_request_and_get_response(cmdid, pyd_tid)
            exc_name, exc_desc, _, _  = parse_exception_details(resp_args, include_stack=False)

        ptvsd.comm.client.send_event('stopped', {
            'reason': reason,
            'threadId': vsc_tid,
            'text': exc_name,
            'description': exc_desc,
            'allThreadsStopped': True,
            'preserveFocusHint': reason not in ['step', 'exception', 'breakpoint'],
        })

    @staticmethod
    def CMD_THREAD_RUN(args):
        pass  # Ignore: only send continued on CMD_THREAD_RESUME_SINGLE_NOTIFICATION

    @staticmethod
    def CMD_THREAD_RESUME_SINGLE_NOTIFICATION(args):
        resumed_info = json.loads(args)
        pyd_tid = resumed_info['thread_id']

        try:
            vsc_tid = thread_map.to_vscode(pyd_tid, autogen=False)
        except KeyError:
            pass
        else:
            ptvsd.comm.client.send_event('continued', {'threadId': vsc_tid})

    @staticmethod
    def CMD_SEND_CURR_EXCEPTION_TRACE(args):
        pass

    @staticmethod
    def CMD_SEND_CURR_EXCEPTION_TRACE_PROCEEDED(args):
        pass

    @staticmethod
    def CMD_WRITE_TO_CONSOLE(args):
        xml = parse_xml_response(args)
        ctx = xml.io['ctx']
        category = 'stdout' if ctx == '1' else 'stderr'
        content = ptvsd.util.unquote(xml.io['s'])
        ptvsd.comm.client.send_event('output', {
            'category': category,
            'output': content,
        })

    @staticmethod
    def CMD_GET_BREAKPOINT_EXCEPTION(args):
        # If pydevd sends exception info from a failed breakpoint condition, just ignore.
        pass

    @staticmethod
    def CMD_PROCESS_CREATED(args):
        pass
