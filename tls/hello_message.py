from __future__ import absolute_import, division, print_function

from enum import Enum

from characteristic import attributes

from six import BytesIO

from tls import _constructs


@attributes(['major', 'minor'])
class ClientVersion(object):
    """
    An object representing a ClientVersion struct.
    """


@attributes(['gmt_unix_time', 'random_bytes'])
class Random(object):
    """
    An object representing a Random struct.
    """


@attributes(['type', 'data'])
class Extension(object):
    """
    An object representing an Extension struct.
    """


@attributes(['client_version', 'random', 'session_id', 'cipher_suites',
             'compression_methods', 'extensions'])
class ClientHello(object):
    """
    An object representing a ClientHello message.
    """


class ExtensionType(Enum):
    SIGNATURE_ALGORITHMS = 13
    # XXX: See http://tools.ietf.org/html/rfc5246#ref-TLSEXT


def parse_client_hello(bytes):
    """
    Parse a ``ClientHello`` struct.

    :param bytes: the bytes representing the input.
    :return: ClientHello object.
    """
    construct = _constructs.ClientHello.parse(bytes)
    # XXX Is there a better way in Construct to parse an array of
    # variable-length structs?
    extensions = []
    extensions_io = BytesIO(construct.extensions_bytes)
    while extensions_io.tell() < construct.extensions_length:
        extension_construct = _constructs.Extension.parse_stream(extensions_io)
        extensions.append(
            Extension(type=ExtensionType(extension_construct.type),
                      data=extension_construct.data))
    return ClientHello(
        client_version=ClientVersion(
            major=construct.client_version.major,
            minor=construct.client_version.minor,
        ),
        random=Random(
            gmt_unix_time=construct.random.gmt_unix_time,
            random_bytes=construct.random.random_bytes,
        ),
        session_id=construct.session_id.session_id,
        # TODO: cipher suites should be enums
        cipher_suites=construct.cipher_suites.cipher_suites,
        compression_methods=construct.compression_methods.compression_methods,
        extensions=extensions,
    )
