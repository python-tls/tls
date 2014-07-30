from characteristic import attributes

from enum import Enum

from tls import _constructs


@attributes(['major', 'minor'])
class ProtocolVersion(object):
    """
    An object representing a ProtocolVersion struct.
    """


@attributes(['type', 'version', 'length', 'fragment'])
class TLSPlaintext(object):
    """
    An object representing a TLSPlaintext struct.
    """


class ContentType(Enum):
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23


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
        length=construct.length,
        fragment=construct.fragment)
