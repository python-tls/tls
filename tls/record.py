from characteristic import attributes

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


def parse_tls_plaintext(bytes):
    """
    Parse a ``TLSPlaintext`` struct.

    :param bytes: the bytes representing the input.
    :return: TLSPlaintext object.
    """
    construct = _constructs.TLSPlaintext.parse(bytes)
    return TLSPlaintext(
        type=construct.type,
        version=ProtocolVersion(
            major=construct.version.major,
            minor=construct.version.minor),
        length=construct.length,
        fragment=construct.fragment)
