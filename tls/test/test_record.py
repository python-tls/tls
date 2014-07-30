"""
Tests for the tls.record module.
"""

from tls.record import parse_tls_plaintext, ContentType


class TestRecordParsing(object):
    """
    Tests for parsing of TLS records.
    """

    def test_parse_tls_plaintext_handshake(self):
        """
        :func:`parse_tls_plaintext` returns an instance of
        :class:`TLSPlaintext`, which has attributes representing all the fields
        in the TLSPlaintext struct.
        """
        packet = (
            chr(22) # type
            + chr(3) # major version
            + chr(3) # minor version
            + chr(0) + chr(10) # big-endian length
            + '0123456789' # fragment
        )
        record = parse_tls_plaintext(packet)
        # TODO: actually type should be a "constant" object, not an int.
        assert record.type == ContentType.handshake
        assert record.version.major == 3
        assert record.version.minor == 3
        assert record.length == 10
        assert record.fragment == '0123456789'
