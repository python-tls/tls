from __future__ import absolute_import, division, print_function

from characteristic import attributes

from tls import _constructs


@attributes([])
class HelloRequest(object):
    """
    An object representing a HelloRequest message.
    """


def parse_hello_request():
    """
    Parse a ``HelloRequest`` struct.
    """
