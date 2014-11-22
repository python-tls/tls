# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from construct.core import Construct

import pytest

from tls.utils import UBInt24, _UBInt24


@pytest.mark.parametrize("byte,number", [
    (b"\x00\x00\xFF", 255),
    (b"\x00\xFF\xFF", 65535),
    (b"\xFF\xFF\xFF", 16777215)
])
class TestUBInt24(object):
    def test_encode(self, byte, number):
        ubint24 = _UBInt24(Construct(name="test"))
        assert ubint24._encode(number, context=object()) == byte

    def test_decode(self, byte, number):
        ubint24 = _UBInt24(Construct(name="test"))
        assert ubint24._decode(byte, context=object()) == number


def test_ubint24():
    assert isinstance(UBInt24("test"), _UBInt24)
