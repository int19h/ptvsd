# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root
# for license information.

from __future__ import absolute_import, print_function, with_statement

import logging
import os
import sys

import ptvsd


try:
    logfile = os.environ['PTVSD_LOG']
    is_logging = True
except KeyError:
    logfile = '-'
    is_logging = True #False


logger = logging.getLogger(ptvsd.__name__)
logger.propagate = False
logger.setLevel(logging.WARNING)

formatter = logging.Formatter('[%(asctime)s] %(message)s\n')

handler = logging.StreamHandler(sys.__stderr__)
handler.setFormatter(formatter)
logger.addHandler(handler)

if is_logging:
    logger.setLevel(logging.DEBUG)
    if logfile and logfile != '-':
        handler = logging.FileHandler(logfile, 'w')
        handler.setFormatter(formatter)
        logger.addHandler(handler)


log = logger.log
debug = logger.debug
info = logger.info
warning = logger.warning
error = logger.error
critical = logger.critical
exception = logger.exception
