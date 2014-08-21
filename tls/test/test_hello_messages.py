from __future__ import absolute_import, division, print_function

import pytest

from tls.hello_message import (
    HelloRequest, parse_hello_request
)


class TestHelloRequest(object):
    """
    Test for parsing of the HelloRequest method of TLS.
    """

    def test_parse_hello_request(self):
        """
        :func:`parse_hello_request` returns an instance of
        :class:`HelloRequest`.
        """

        # packet = ()  -- since it doesn't need to take any bytes
        record = parse_hello_request()
        assert isinstance(record, HelloRequest)

class TestClientHello(object):
    """
    Tests for the parsing of ClientHello messages.
    """
"""
   struct {
       uint32 gmt_unix_time;
       opaque random_bytes[28];
   } Random;

   opaque SessionID<0..32>;

   uint8 CipherSuite[2];

   enum { null(0), (255) } CompressionMethod;

   struct {
       ProtocolVersion client_version;
       Random random;
       SessionID session_id;
       CipherSuite cipher_suites<2..2^16-2>;
       CompressionMethod compression_methods<1..2^8-1>;
       select (extensions_present) {
           case false:
               struct {};
           case true:
               Extension extensions<0..2^16-1>;
       };
   } ClientHello;

"""

    def test_parse_client_hello(self):
        """
        :func:`parse_client_hello` returns an instance of
        :class:`ClientHello`.
        """
        packet = (
            b''  # client_version
            b''  # random
            b''  # session_id
            b''  # cipher_suites
            b''  # compression_methods
          #  b''  # XXX: extentions ???
        )
        record = parse_client_hello(packet)
        assert record.client_version == None
        assert record.random == None
        assert record.session_id == None
        assert record.cipher_suites == None
        assert record.compression_methods == None
# XXX        assert record.

