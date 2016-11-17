# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from construct.adapters import ValidationError

import pytest

from tls._common import enums

from tls.ciphersuites import CipherSuites

from tls.hello_message import ClientHello, ServerHello


class TestClientHello(object):
    """
    Tests for the parsing of ClientHello messages.
    """

    no_extensions_packet = (
        b'\x03\x00'  # client_version
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x20'  # session_id.length
        b'01234567890123456789012345678901'  # session_id.session_id
        b'\x00\x02'  # cipher_suites length
        b'\x00\x6B'  # cipher_suites
        b'\x01'  # compression_methods length
        b'\x00'  # compression_methods
        b'\x00\x00'  # extensions.length
        b''  # extensions.extension_type
        b''  # extensions.extensions
    )

    supported_signature_list_extension_data = (
        b'\x00\x0D'  # extensions[0].extension_type
        b'\x00\x16'  # extensions[0].length
        b'\x00\x14'  # The length of signature_algorithms vector
        b'\x04\x01'  # SHA256, RSA
        b'\x05\x01'  # SHA384, RSA
        b'\x06\x01'  # SHA512, RSA
        b'\x02\x01'  # SHA1, RSA
        b'\x04\x03'  # SHA256, ECDSA
        b'\x05\x03'  # SHA384, ECDSA
        b'\x06\x03'  # SHA512, ECDSA
        b'\x02\x03'  # SHA1, ECDSA
        b'\x04\x02'  # SHA256, DSA
        b'\x02\x02'  # SHA1, DSA
    )

    extensions_packet = (
        b'\x03\x00'  # client_version
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x00'  # session_id.length
        b''  # session_id.session_id
        b'\x00\x02'  # cipher_suites length
        b'\x00\x6B'  # cipher_suites
        b'\x01'  # compression_methods length
        b'\x00'  # compression_methods
        b'\x00\x1a'  # extensions length
    ) + supported_signature_list_extension_data

    compression_methods_too_short_packet = (
        b'\x03\x00'  # client_version
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x00'  # session_id.length
        b''  # session_id.session_id
        b'\x00\x02'  # cipher_suites length
        b'\x00\x6B'  # cipher_suites
        b'\x00'  # compression_methods length
        b''  # compression_methods
        b'\x00\x1a'  # extensions length
    ) + supported_signature_list_extension_data

    cipher_suites_too_short_packet = (
        b'\x03\x00'  # client_version
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x00'  # session_id.length
        b''  # session_id.session_id
        b'\x00\x00'  # cipher_suites length
        b''  # cipher_suites
        b'\x01'  # compression_methods length
        b'\x00'  # compression_methods
        b'\x00\x00'  # extensions length
        b''  # extensions.extensions.extension_type
        b''  # extensions.extensions.extensions_data length
        b''  # extensions.extensions.extension_data
    )

    def test_resumption_no_extensions(self):
        """
        :func:`parse_client_hello` returns an instance of
        :class:`ClientHello`.
        """
        record = ClientHello.from_bytes(self.no_extensions_packet)
        assert isinstance(record, ClientHello)
        assert record.client_version.major == 3
        assert record.client_version.minor == 0
        assert record.random.gmt_unix_time == 16909060
        assert record.random.random_bytes == b'0123456789012345678901234567'
        assert record.session_id == b'01234567890123456789012345678901'
        assert record.cipher_suites == [
            CipherSuites.TLS_NULL_WITH_NULL_NULL,
            CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        ]
        assert record.compression_methods == [0]
        assert len(record.extensions) == 0

    def test_as_bytes_no_extensions(self):
        """
        :func:`ClientHello.as_bytes` returns the bytes it was created with
        """
        record = ClientHello.from_bytes(self.no_extensions_packet)
        assert record.as_bytes() == self.no_extensions_packet

    def test_as_bytes_with_extensions(self):
        """
        :func:`ClientHello.as_bytes` returns the bytes it was created with
        """
        record = ClientHello.from_bytes(self.extensions_packet)
        assert record.as_bytes() == self.extensions_packet

    def test_parse_client_hello_extensions(self):
        record = ClientHello.from_bytes(self.extensions_packet)
        assert len(record.extensions) == 1
        assert (record.extensions[0].type ==
                enums.ExtensionType.SIGNATURE_ALGORITHMS)
        assert len(record.extensions[0].data) == 10

    def test_parse_client_hello_compression_methods_too_short(self):
        """
        :py:func:`tls.hello_message.ClientHello` fails to parse a
        packet whose ``compression_methods`` is too short.
        """
        with pytest.raises(ValidationError) as exc_info:
            ClientHello.from_bytes(self.compression_methods_too_short_packet)
        assert exc_info.value.args == ('invalid object', 0)

    def test_as_bytes_client_hello_compression_methods_too_short(self):
        """
        :py:func:`tls.hello_message.ClientHello` fails to construct a
        packet whose ``compression_methods`` would be too short.
        """
        record = ClientHello.from_bytes(self.no_extensions_packet)
        record.compression_methods = []
        with pytest.raises(ValidationError) as exc_info:
            record.as_bytes()
        assert exc_info.value.args == ('invalid object', 0)

    def test_parse_client_hello_cipher_suites(self):
        """
        :py:func:`tls.hello_message.ClientHello` fails to parse a
        packet whose ``cipher_suites`` is too short.
        """
        with pytest.raises(ValidationError) as exc_info:
            ClientHello.from_bytes(self.cipher_suites_too_short_packet)
        assert exc_info.value.args == ('invalid object', 0)

    def test_as_bytes_client_hello_cipher_suites(self):
        """
        :py:func:`tls.hello_message.ClientHello` fails to construct a
        packet whose ``cipher_suites`` would be too short.
        """
        record = ClientHello.from_bytes(self.no_extensions_packet)
        record.cipher_suites = []
        with pytest.raises(ValidationError) as exc_info:
            record.as_bytes()
        assert exc_info.value.args == ('invalid object', 0)


class TestServerHello(object):
    """
    Tests for the parsing of ServerHello messages.
    """
    no_extensions_packet = (
        b'\x03\x00'  # server_version
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x20'  # session_id.length
        b'01234567890123456789012345678901'  # session_id
        b'\x00\x6B'  # cipher_suite
        b'\x00'  # compression_method
        b'\x00\x00'  # extensions.length
        b''  # extensions.extension_type
        b''  # extensions.extensions
    )

    supported_signature_list_extension_data = (
        b'\x00\x0D'  # extensions[0].extension_type
        b'\x00\x16'  # extensions[0].length
        b'\x00\x14'  # The length of signature_algorithms vector
        b'\x04\x01'  # SHA256, RSA
        b'\x05\x01'  # SHA384, RSA
        b'\x06\x01'  # SHA512, RSA
        b'\x02\x01'  # SHA1, RSA
        b'\x04\x03'  # SHA256, ECDSA
        b'\x05\x03'  # SHA384, ECDSA
        b'\x06\x03'  # SHA512, ECDSA
        b'\x02\x03'  # SHA1, ECDSA
        b'\x04\x02'  # SHA256, DSA
        b'\x02\x02'  # SHA1, DSA
    )

    extensions_packet = (
        b'\x03\x00'  # server_version
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x20'  # session_id.length
        b'01234567890123456789012345678901'  # session_id
        b'\x00\x6B'  # cipher_suite
        b'\x00'  # compression_method
        b'\x00\x1a'  # extensions length
    ) + supported_signature_list_extension_data

    def test_parse_server_hello(self):
        """
        :func:`parse_server_hello` returns an instance of
        :class:`ServerHello`.
        """
        record = ServerHello.from_bytes(self.no_extensions_packet)
        assert isinstance(record, ServerHello)
        assert record.server_version.major == 3
        assert record.server_version.minor == 0
        assert record.random.gmt_unix_time == 16909060
        assert record.random.random_bytes == b'0123456789012345678901234567'
        assert record.session_id == b'01234567890123456789012345678901'
        assert record.cipher_suite == b'\x00\x6B'
        assert record.compression_method == enums.CompressionMethod.NULL
        assert len(record.extensions) == 0

    def test_parse_server_hello_extensions(self):
        """
        :func:`parse_server_hello` returns an instance of :class:`ServerHello`
        with extensions, when the extension bytes are present in the input.
        """
        record = ServerHello.from_bytes(self.extensions_packet)
        assert len(record.extensions) == 1
        assert (record.extensions[0].type ==
                enums.ExtensionType.SIGNATURE_ALGORITHMS)
        assert len(record.extensions[0].data) == 10

    def test_as_bytes_no_extensions(self):
        """
        :func:`ServerHello.as_bytes` returns the bytes it was created with
        """
        record = ServerHello.from_bytes(self.no_extensions_packet)
        assert record.as_bytes() == self.no_extensions_packet

    def test_as_bytes_with_extensions(self):
        """
        :func:`ServerHello.as_bytes` returns the bytes it was created with
        """
        record = ServerHello.from_bytes(self.extensions_packet)
        assert record.as_bytes() == self.extensions_packet
