from __future__ import absolute_import, division, print_function

from construct.core import FieldError

import pytest

from tls.record import (
    ContentType, parse_tls_ciphertext, parse_tls_compressed,
    parse_tls_plaintext
)


class TestTLSPlaintextParsing(object):
    """
    Tests for parsing of TLSPlaintext records.
    """

    def test_parse_tls_plaintext_handshake(self):
        """
        :func:`parse_tls_plaintext` returns an instance of
        :class:`TLSPlaintext`, which has attributes representing all the fields
        in the TLSPlaintext struct.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\x00\x0A'  # big-endian length
            b'0123456789'  # fragment
        )
        record = parse_tls_plaintext(packet)
        assert record.type == ContentType.HANDSHAKE
        assert record.version.major == 3
        assert record.version.minor == 3
        assert record.fragment == b'0123456789'

    def test_parse_tls_plaintext_wrong_type(self):
        """
        Raise an error when the type is not one of those defined in ContentType
        """
        packet = (
            b'\x1a'  # invalid type
            b'\x03'
            b'\x03'
            b'\x00\x0A'
            b'0123456789'
        )
        with pytest.raises(ValueError) as exc_info:
            parse_tls_plaintext(packet)
        assert str(exc_info.value) == "26 is not a valid ContentType"

    def test_incomplete_packet(self):
        """
        Reject an incomplete packet
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # minor version
            b'\x00\x0A'  # big-endian length
            b'0123456789'  # fragment
        )
        with pytest.raises(FieldError) as exc_info:
            parse_tls_plaintext(packet)
        assert str(exc_info.value) == "expected 2608, found 9"

    def test_not_enough_data_to_fragment(self):
        """
        Detect insufficient data to fragment.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\x00\x0A'  # big-endian length
            b'12'  # fragment
        )
        with pytest.raises(FieldError) as exc_info:
            parse_tls_plaintext(packet)
        assert str(exc_info.value) == "expected 10, found 2"

    def test_as_bytes(self):
        """
        Construct a TLSPlaintext object as bytes.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\x00\x0A'  # big-endian length
            b'0123456789'  # fragment
        )
        record = parse_tls_plaintext(packet)
        assert record.as_bytes() == packet


class TestTLSCompressedParsing(object):
    """
    Tests for parsing of TLSCompressed records.
    """

    def test_parse_tls_compressed_handshake(self):
        """
        :class:`TLSCmpressed`, which has attributes representing all the fields
        in the TLSCompressed struct.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\x00\x0A'  # big-endian length
            b'0123456789'  # fragment
        )
        record = parse_tls_compressed(packet)
        assert record.type == ContentType.HANDSHAKE
        assert record.version.major == 3
        assert record.version.minor == 3
        assert record.fragment == b'0123456789'

    def test_parse_tls_compressed_wrong_type(self):
        """
        Raise an error when the type is not one of those defined in ContentType
        """
        packet = (
            b'\x1a'  # invalid type
            b'\x03'
            b'\x03'
            b'\x00\x0A'
            b'0123456789'
        )
        with pytest.raises(ValueError) as exc_info:
            parse_tls_compressed(packet)
        assert str(exc_info.value) == "26 is not a valid ContentType"

    def test_incomplete_packet(self):
        """
        Reject an incomplete packet
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # minor version
            b'\x00\x0A'  # big-endian length
            b'0123456789'  # fragment
        )
        with pytest.raises(FieldError) as exc_info:
            parse_tls_compressed(packet)
        assert str(exc_info.value) == "expected 2608, found 9"

    def test_not_enough_data_to_fragment(self):
        """
        Detect insufficient data to fragment.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\x00\x0A'  # big-endian length
            b'12'  # fragment
        )
        with pytest.raises(FieldError) as exc_info:
            parse_tls_compressed(packet)
        assert str(exc_info.value) == "expected 10, found 2"


class TestTLSCiphertextParser(object):
    """
    Tests for parsing of TLSCiphertext records.
    """

    def test_parse_tls_ciphertext_handshake(self):
        """
        :class:`TLSCiphertext`, which has attributes representing all the
        fields in the TLSCiphertext struct.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\x00\x0A'  # big-endian length
            b'0123456789'  # fragment
        )
        record = parse_tls_ciphertext(packet)
        assert record.type == ContentType.HANDSHAKE
        assert record.version.major == 3
        assert record.version.minor == 3
        assert record.fragment == b'0123456789'
