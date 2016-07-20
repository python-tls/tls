# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from construct.adapters import ValidationError

from construct.core import FieldError

import pytest

from tls._common import enums

from tls.record import (ProtocolVersion, TLSCiphertext, TLSCompressed,
                        TLSPlaintext)


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
        record = TLSPlaintext.from_bytes(packet)
        assert record.type == enums.ContentType.HANDSHAKE
        assert record.version.major == 3
        assert record.version.minor == 3
        assert record.fragment == b'0123456789'

    def test_parse_tls_plaintext_wrong_type(self):
        """
        Raise an error when the type is not one of those defined in
        :class:`enums.ContentType`.
        """
        packet = (
            b'\x1a'  # invalid type
            b'\x03'
            b'\x03'
            b'\x00\x0A'
            b'0123456789'
        )
        with pytest.raises(ValueError) as exc_info:
            TLSPlaintext.from_bytes(packet)
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
            TLSPlaintext.from_bytes(packet)
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
            TLSPlaintext.from_bytes(packet)
        assert str(exc_info.value) == "expected 10, found 2"

    def test_parse_fragment_too_long(self):
        """
        :py:func:`tls.record.TLSPlaintext` fails to parse a packet
        containing a longer-than-allowed fragment.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\xff\xff' +    # big-endian length
            (b'a' * 0xFFFF)  # fragment
        )
        with pytest.raises(ValidationError) as exc_info:
            TLSPlaintext.from_bytes(packet)
        assert exc_info.value.args == ('invalid object', 0xFFFF)

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
        record = TLSPlaintext.from_bytes(packet)
        assert record.as_bytes() == packet

    def test_as_bytes_fragment_too_long(self):
        """
        :py:func:`tls.record.TLSPlaintext` fails to construct a packet
        with a longer-than-allowed fragment.
        """
        plaintext = TLSPlaintext(type=enums.ContentType.HANDSHAKE,
                                 version=ProtocolVersion(major=3, minor=3),
                                 fragment=b'a' * 0xFFFF)
        with pytest.raises(ValidationError) as exc_info:
            plaintext.as_bytes()
        assert exc_info.value.args == ('invalid object', 0xFFFF)


class TestTLSCompressedParsing(object):
    """
    Tests for parsing of TLSCompressed records.
    """

    def test_parse_tls_compressed_handshake(self):
        """
        :class:`TLSCompressed`, which has attributes representing all
        the fields in the TLSCompressed struct.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\x00\x0A'  # big-endian length
            b'0123456789'  # fragment
        )
        record = TLSCompressed.from_bytes(packet)
        assert record.type == enums.ContentType.HANDSHAKE
        assert record.version.major == 3
        assert record.version.minor == 3
        assert record.fragment == b'0123456789'

    def test_parse_tls_compressed_wrong_type(self):
        """
        Raise an error when the type is not one of those defined in
        :class:`enums.ContentType`.
        """
        packet = (
            b'\x1a'  # invalid type
            b'\x03'
            b'\x03'
            b'\x00\x0A'
            b'0123456789'
        )
        with pytest.raises(ValueError) as exc_info:
            TLSCompressed.from_bytes(packet)
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
            TLSCompressed.from_bytes(packet)
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
            TLSCompressed.from_bytes(packet)
        assert str(exc_info.value) == "expected 10, found 2"

    def test_fragment_too_long(self):
        """
        :py:func:`tls.record.TLSCompressed` rejects a packet
        containing a longer-than-allowed fragment.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\xff\xff' +    # big-endian length
            (b'a' * 0xFFFF)  # fragment
        )
        with pytest.raises(ValidationError) as exc_info:
            TLSCompressed.from_bytes(packet)
        assert exc_info.value.args == ('invalid object', 0xFFFF)


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
        record = TLSCiphertext.from_bytes(packet)
        assert record.type == enums.ContentType.HANDSHAKE
        assert record.version.major == 3
        assert record.version.minor == 3
        assert record.fragment == b'0123456789'

    def test_fragment_too_long(self):
        """
        :py:func:`TLSCiphertext` rejects a packet containing a
        longer-than-allowed fragment.
        """
        packet = (
            b'\x16'  # type
            b'\x03'  # major version
            b'\x03'  # minor version
            b'\xff\xff' +    # big-endian length
            (b'a' * 0xFFFF)  # fragment
        )
        with pytest.raises(ValidationError) as exc_info:
            TLSCiphertext.from_bytes(packet)
        assert exc_info.value.args == ('invalid object', 0xFFFF)
