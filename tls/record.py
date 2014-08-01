from enum import Enum

from characteristic import attributes

from tls import _constructs


@attributes(['major', 'minor'])
class ProtocolVersion(object):
    """
    An object representing a ProtocolVersion struct.
    """


@attributes(['type', 'version', 'fragment'])
class TLSPlaintext(object):
    """
    An object representing a TLSPlaintext struct.
    """


@attributes(['type', 'version', 'fragment'])
class TLSCompressed(object):
    """
    An object representing a TLSCompressed struct.
    """


class ContentType(Enum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


def parse_tls_plaintext(bytes):
    """
    Parse a ``TLSPlaintext`` struct.

    :param bytes: the bytes representing the input.
    :return: TLSPlaintext object.
    """
    construct = _constructs.TLSPlaintext.parse(bytes)
    return TLSPlaintext(
        type=ContentType(construct.type),
        version=ProtocolVersion(
            major=construct.version.major,
            minor=construct.version.minor),
        fragment=construct.fragment)


def parse_tls_compressed(bytes):
    """
    Parse a ``TLSCompressed`` struct.

    :param bytes: the bytes representing the input.
    :return: TLSCompressed object.
    """
    construct = _constructs.TLSCompressed.parse(bytes)
    return TLSCompressed(
        type=ContentType(construct.type),
        version=ProtocolVersion(
            major=construct.version.major,
            minor=construct.version.minor),
        fragment=construct.fragment)
