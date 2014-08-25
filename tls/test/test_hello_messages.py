from __future__ import absolute_import, division, print_function

from tls.hello_message import (
    ClientHello, CompressionMethod, ExtensionType, parse_client_hello
)


class TestClientHello(object):
    """
    Tests for the parsing of ClientHello messages.
    """

    def test_parse_client_hello(self):
        """
        :func:`parse_client_hello` returns an instance of
        :class:`ClientHello`.
        """
        packet = (
            b'\x03\x00'  # client_version
            b'\x01\x02\x03\x04'  # random.gmt_unix_time
            b'0123456789012345678901234567'  # random.random_bytes
            b'01234567890123456789012345678901'  # session_id
            b'\x01\x02'  # cipher_suites
            b'\x00'  # compression_methods
            b'\x00\x0D'  # extensions.extension_type
            b''  # extensions.extension_data
        )
        record = parse_client_hello(packet)
        assert isinstance(record, ClientHello)
        assert record.client_version.major == 3
        assert record.client_version.minor == 0
        assert record.random.gmt_unix_time == 16909060
        assert record.random.random_bytes == b'0123456789012345678901234567'
        assert record.session_id == b'01234567890123456789012345678901'
        assert record.cipher_suites == [1, 2]
        assert record.compression_methods == CompressionMethod.NULL
        assert record.extensions.extension_type == \
            ExtensionType.SIGNATURE_ALGORITHMS
        assert record.extensions.extension_data == b''
