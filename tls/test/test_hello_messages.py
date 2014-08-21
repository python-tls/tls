from __future__ import absolute_import, division, print_function

import pytest

from tls.hello_message import (
    HelloRequest, parse_hello_request
)


class TestHelloRequest(object):
    """
    Test for parsing of the HelloRequest method of TLS.
    """

    def test_parse_hello_request(self):
        """
        :func:`parse_hello_request` returns an instance of
        :class:`HelloRequest`.
        """

        # packet = ()  -- since it doesn't need to take any bytes
        record = parse_hello_request()
        assert isinstance(record, HelloRequest)
