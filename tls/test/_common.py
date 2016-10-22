# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
"""
Components that are common to ``tls``' test suite and importable.  For
non-importable py.test extensions, such as fixtures, see
``conftest.py`` in the root directory.
"""

from __future__ import absolute_import, division, print_function

import pytest


hypothesis_test = pytest.mark.skipif(
    "not config.getoption('--run-hypothesis')",
    reason="need --run-hypothesis to run Hypothesis tests")
