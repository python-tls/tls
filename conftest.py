# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
"""
``py.test``-specific configuration.  Importable components live in
:py:module:`tls.test._common`.
"""

from __future__ import absolute_import, division, print_function


def pytest_addoption(parser):
    """
    Makes the following command line options available:

    ::
        --run-hypothesis
    """
    parser.addoption("--run-hypothesis",
                     action="store_true",
                     default=False,
                     help="Run the hypothesis tests.  Defaults to False")
