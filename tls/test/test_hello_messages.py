from __future__ import absolute_import, division, print_function

from tls.hello_message import (
    ClientHello, CompressionMethod, ExtensionType, ServerHello,
    parse_client_hello, parse_server_hello
)


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
        b'\x00\x08'  # extensions.length
        b'\x00\x0D'  # extensions.extensions.extension_type
        b'\x00\x04'  # extensions.extensions.extensions_data length
        b'abcd'  # extensions.extensions.extension_data
    )

    def test_resumption_no_extensions(self):
        """
        :func:`parse_client_hello` returns an instance of
        :class:`ClientHello`.
        """
        record = parse_client_hello(self.no_extensions_packet)
        assert isinstance(record, ClientHello)
        assert record.client_version.major == 3
        assert record.client_version.minor == 0
        assert record.random.gmt_unix_time == 16909060
        assert record.random.random_bytes == b'0123456789012345678901234567'
        assert record.session_id == b'01234567890123456789012345678901'
        assert record.cipher_suites == [b'\x00\x6B']
        assert record.compression_methods == [0]
        assert len(record.extensions) == 0

    def test_as_bytes_no_extensions(self):
        """
        :func:`ClientHello.as_bytes` returns the bytes it was created with
        """
        record = parse_client_hello(self.no_extensions_packet)
        assert record.as_bytes() == self.no_extensions_packet

    def test_parse_client_hello_extensions(self):
        record = parse_client_hello(self.extensions_packet)
        assert len(record.extensions) == 1
        assert record.extensions[0].type == ExtensionType.SIGNATURE_ALGORITHMS
        assert record.extensions[0].data == b'abcd'


class TestServerHello(object):
    """
    Tests for the parsing of ServerHello messages.
    """

    def test_parse_server_hello(self):
        """
        :func:`parse_server_hello` returns an instance of
        :class:`ServerHello`.
        """
        packet = (
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
        record = parse_server_hello(packet)
        assert isinstance(record, ServerHello)
        assert record.server_version.major == 3
        assert record.server_version.minor == 0
        assert record.random.gmt_unix_time == 16909060
        assert record.random.random_bytes == b'0123456789012345678901234567'
        assert record.session_id == b'01234567890123456789012345678901'
        assert record.cipher_suite == b'\x00\x6B'
        assert record.compression_method == CompressionMethod.NULL
        assert len(record.extensions) == 0

    def test_parse_server_hello_extensions(self):
        """
        :func:`parse_server_hello` returns an instance of
        :class:`ServerHello`.
        """
        packet = (
            b'\x03\x00'  # server_version
            b'\x01\x02\x03\x04'  # random.gmt_unix_time
            b'0123456789012345678901234567'  # random.random_bytes
            b'\x20'  # session_id.length
            b'01234567890123456789012345678901'  # session_id
            b'\x00\x6B'  # cipher_suite
            b'\x00'  # compression_method
            b'\x00\x08'  # extensions.length
            b'\x00\x0D'  # extensions.extensions.extension_type
            b'\x00\x04'  # extensions.extensions.extensions_data length
            b'abcd'  # extensions.extensions.extension_data
        )
        record = parse_server_hello(packet)
        assert len(record.extensions) == 1
        assert record.extensions[0].type == ExtensionType.SIGNATURE_ALGORITHMS
        assert record.extensions[0].data == b'abcd'
