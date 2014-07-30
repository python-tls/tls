"""
Tests for the tls.record module.
"""

from construct.core import FieldError

from tls.record import ContentType, parse_tls_plaintext


class TestRecordParsing(object):
    """
    Tests for parsing of TLS records.

    TODO: We need:
    1. an incomplete packet being rejected
    2. Not enough data to fragment
    """

    def test_parse_tls_plaintext_handshake(self):
        """
        :func:`parse_tls_plaintext` returns an instance of
        :class:`TLSPlaintext`, which has attributes representing all the fields
        in the TLSPlaintext struct.
        """
        packet = (
            b'\x16'  # type
            + b'\x03'  # major version
            + b'\x03'  # minor version
            + b'\x00' + b'\n'  # big-endian length
            + b'0123456789'  # fragment
        )
        record = parse_tls_plaintext(packet)
        assert record.type == ContentType.HANDSHAKE
        assert record.version.major == 3
        assert record.version.minor == 3
        assert record.length == 10
        assert record.fragment == b'0123456789'

    def test_parse_tls_plaintext_wrong_type(self):
        """
        Raise an error when the type is not one of those defined in ContentType
        """
        packet = (
            b'\x1a'  # invalid type
            + b'\x03'
            + b'\x03'
            + b'\x00' + b'\n'
            + b'0123456789'
        )
        try:
            parse_tls_plaintext(packet)
        except ValueError as e:
            assert e.message == "26 is not a valid ContentType"

    def test_incomplete_packet(self):
        """
        Reject an incomplete packet
        """
        packet = (
            b'\x16'  # type
            + b'\x03'  # minor version
            + b'\x00' + b'\n'  # big-endian length
            + b'0123456789'  # fragment
        )
        try:
            parse_tls_plaintext(packet)
        except FieldError as e:
            assert e.message == "expected 2608, found 9"
