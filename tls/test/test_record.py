"""
Tests for the tls.record module.
"""

from tls.record import ContentType, parse_tls_plaintext


class TestRecordParsing(object):
    """
    Tests for parsing of TLS records.

    TODO: We need:
    1. negative tests for type being wrong
    2. an incomplete packet being rejected
    3. Not enough data to fragment
    """

    def test_parse_tls_plaintext_handshake(self):
        """
        :func:`parse_tls_plaintext` returns an instance of
        :class:`TLSPlaintext`, which has attributes representing all the fields
        in the TLSPlaintext struct.
        """
        packet = (
            '\x16'  # type
            + '\x03'  # major version
            + '\x03'  # minor version
            + '\x00' + '\n'  # big-endian length
            + '0123456789'  # fragment
        )
        record = parse_tls_plaintext(packet)
        assert record.type == ContentType.HANDSHAKE
        assert record.version.major == 3
        assert record.version.minor == 3
        assert record.length == 10
        assert record.fragment == b'0123456789'
