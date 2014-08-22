from __future__ import absolute_import, division, print_function

from enum import Enum

from characteristic import attributes

from tls import _constructs


# @attributes([])
class HelloRequest(object):
    """
    An object representing a HelloRequest message.
    """


@attributes(['client_version', 'random', 'session_id', 'cipher_suites', 'compression_methods'])  # TODO: Figure out what to do about extensions present
class ClientHello(object):
    """
    An object representing a ClientHello message.
    """


def parse_hello_request():
    """
    Parse a ``HelloRequest`` struct.
    """
#    construct = _constructs.HelloRequest.parse() # Do we relly need this?
    return HelloRequest()


class CompressionMethod(Enum):
    NULL = 0


def parse_client_hello(bytes):
    """
    Parse a ``ClientHello`` struct.

    :param bytes: the bytes representing the input.
    :return: ClientHello object.
    """

