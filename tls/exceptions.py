# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


class TLSException(Exception):
    """
    This is the root exception from which all other exceptions inherit.
    Lower-level parsing code raises very specific exceptions that higher-level
    code can catch with this exception.
    """


class UnsupportedCipherException(TLSException):
    pass


class UnsupportedExtensionException(TLSException):
    pass


class TLSValidationException(TLSException):
    pass
