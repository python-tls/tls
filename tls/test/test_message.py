# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from tls.hello_message import ClientHello, ProtocolVersion, ServerHello

from tls.message import (
    Certificate, CertificateRequest, ClientCertificateType, Finished,
    Handshake, HandshakeType, HashAlgorithm, HelloRequest, PreMasterSecret,
    ServerDHParams, ServerHelloDone, SignatureAlgorithm
)


class TestCertificateRequestParsing(object):
    """
    Tests for parsing of CertificateRequest messages.
    """
    no_authorities_packet = (
        b'\x01'  # certificate_types length
        b'\x01'  # certificate_types
        b'\x00\x02'  # supported_signature_algorithms length
        b'\x01'  # supported_signature_algorithms.hash
        b'\x01'  # supported_signature_algorithms.signature
        b'\x00\x00'  # certificate_authorities length
        b''  # certificate_authorities
    )
    with_authorities_packet = (
        b'\x01'  # certificate_types length
        b'\x01'  # certificate_types
        b'\x00\x02'  # supported_signature_algorithms length
        b'\x01'  # supported_signature_algorithms.hash
        b'\x01'  # supported_signature_algorithms.signature
        b'\x00\x02'  # certificate_authorities length
        b'03'  # certificate_authorities
    )

    def test_parse_certificate_request(self):
        record = CertificateRequest.from_bytes(self.no_authorities_packet)
        assert record.certificate_types == [ClientCertificateType.RSA_SIGN]
        assert len(record.supported_signature_algorithms) == 1
        assert record.supported_signature_algorithms[0].hash == \
            HashAlgorithm.MD5
        assert record.supported_signature_algorithms[0].signature == \
            SignatureAlgorithm.RSA
        assert record.certificate_authorities == b''

    def test_parse_certificate_request_with_authorities(self):
        record = CertificateRequest.from_bytes(self.with_authorities_packet)
        assert record.certificate_authorities == b'03'

    def test_as_bytes_no_authoritites(self):
        record = CertificateRequest.from_bytes(self.no_authorities_packet)
        assert record.as_bytes() == self.no_authorities_packet

    def test_as_bytes_with_authoritites(self):
        record = CertificateRequest.from_bytes(self.with_authorities_packet)
        assert record.as_bytes() == self.with_authorities_packet


class TestServerDHParamsparsing(object):
    """
    Tests for parsing of ServerDHParams struct.
    """

    def test_parse_struct(self):
        packet = (
            b'\x00\x03'
            b'123'
            b'\x00\x04'
            b'5678'
            b'\x00\x02'
            b'78'
        )
        record = ServerDHParams.from_bytes(packet)
        assert record.dh_p == b'123'
        assert record.dh_g == b'5678'
        assert record.dh_Ys == b'78'


class TestPreMasterSecretParsing(object):
    """
    Tests for parsing of PreMasterSecret struct.
    """

    def test_parse_pre_master_secret(self):
        import os
        r = os.urandom(46)
        packet = (
            b'\x03\x00' + r  # ClientHello.client_version + random
        )
        record = PreMasterSecret.from_bytes(packet)
        assert isinstance(record, PreMasterSecret)
        assert isinstance(record.client_version, ProtocolVersion)
        assert record.client_version.major == 3
        assert record.client_version.minor == 0
        assert record.random == r


class TestCertificateParsing(object):
    """
    Tests for parsing of Certificate messages.
    """
    packet = (
        b'\x00\x00\x00\x07'  # certificate_length
        b'\x00\x00\x00\x03'  # certificate_list.asn1_cert length
        b'ABC'  # certificate_list.asn1_cert
    )

    def test_parse_certificate(self):
        record = Certificate.from_bytes(self.packet)
        assert isinstance(record, Certificate)
        assert len(record.certificate_list) == 1
        assert record.certificate_list[0].asn1_cert == b'ABC'

    def test_as_bytes(self):
        record = Certificate.from_bytes(self.packet)
        assert record.as_bytes() == self.packet


class TestHandshakeStructParsing(object):
    """
    Tests for parsing of Handshake structs.
    """
    client_hello_packet = (
        b'\x03\x00'  # client_version
        b'\x01\x02\x03\x04'  # random.gmt_unix_time
        b'0123456789012345678901234567'  # random.random_bytes
        b'\x00'  # session_id.length
        b''  # session_id.session_id
        b'\x00\x02'  # cipher_suites length
        b'\x00\x6B'  # cipher_suites
        b'\x01'  # compression_methods length
        b'\x00'  # compression_methods
        b'\x00\x08'  # extensions length
        b'\x00\x0D'  # extensions.extensions.extension_type
        b'\x00\x04'  # extensions.extensions.extensions_data length
        b'abcd'  # extensions.extensions.extension_data
    )

    client_hello_handshake_packet = (
        b'\x01'  # msg_type
        b'\x00\x003'  # body length
    ) + client_hello_packet

    server_hello_packet = (
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

    server_hello_handshake_packet = (
        b'\x02'  # msg_type
        b'\x00\x00P'  # body length
    ) + server_hello_packet

    certificate_packet = (
        b'\x00\x00\x00\x07'  # certificate_length
        b'\x00\x00\x00\x03'  # certificate_list.asn1_cert length
        b'ABC'  # certificate_list.asn1_cert
    )

    certificate_handshake_packet = (
        b'\x0B'
        b'\x00\x00\x0b'
    ) + certificate_packet

    certificate_request_packet = (
        b'\x01'  # certificate_types length
        b'\x01'  # certificate_types
        b'\x00\x02'  # supported_signature_algorithms length
        b'\x01'  # supported_signature_algorithms.hash
        b'\x01'  # supported_signature_algorithms.signature
        b'\x00\x00'  # certificate_authorities length
        b''  # certificate_authorities
    )

    certificate_request_handshake = (
        b'\x0D'
        b'\x00\x00\x08'
    ) + certificate_request_packet

    server_key_exchange_handshake = (
        b'\x0C'
        b'\x00\x00\x00'
        b''
    )

    hello_request_handshake = (
        b'\x00'
        b'\x00\x00\x00'
        b''
    )

    server_hello_done_handshake = (
        b'\x0E'
        b'\x00\x00\x00'
        b''
    )

    finished_handshake = (
        b'\x14'
        b'\x00\x00\x14'
        b'some-encrypted-bytes'
    )

    def test_parse_client_hello_in_handshake(self):
        record = Handshake.from_bytes(self.client_hello_handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.CLIENT_HELLO
        assert record.length == 51
        assert isinstance(record.body, ClientHello)

    def test_parse_server_hello_in_handshake(self):
        record = Handshake.from_bytes(self.server_hello_handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.SERVER_HELLO
        assert record.length == 80
        assert isinstance(record.body, ServerHello)

    def test_parse_certificate_request_in_handshake(self):
        record = Handshake.from_bytes(
            self.certificate_request_handshake
        )
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.CERTIFICATE_REQUEST
        assert record.length == 8
        assert isinstance(record.body, CertificateRequest)

    def test_parse_certificate_in_handshake(self):
        record = Handshake.from_bytes(self.certificate_handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.CERTIFICATE
        assert record.length == 11
        assert isinstance(record.body, Certificate)

    def test_parse_hello_request(self):
        record = Handshake.from_bytes(self.hello_request_handshake)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.HELLO_REQUEST
        assert record.length == 0
        assert isinstance(record.body, HelloRequest)

    def test_server_hello_done(self):
        record = Handshake.from_bytes(self.server_hello_done_handshake)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.SERVER_HELLO_DONE
        assert record.length == 0
        assert isinstance(record.body, ServerHelloDone)

    def test_not_implemented(self):
        record = Handshake.from_bytes(self.server_key_exchange_handshake)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.SERVER_KEY_EXCHANGE
        assert record.length == 0
        assert record.body is None

    def test_finished(self):
        record = Handshake.from_bytes(self.finished_handshake)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.FINISHED
        assert record.length == 20
        assert isinstance(record.body, Finished)
        assert record.body.verify_data == b'some-encrypted-bytes'

    def test_as_bytes_server_hello_packet(self):
        record = Handshake.from_bytes(self.server_hello_handshake_packet)
        assert record.as_bytes() == self.server_hello_handshake_packet

    def test_as_bytes_client_hello_packet(self):
        record = Handshake.from_bytes(self.client_hello_handshake_packet)
        assert record.as_bytes() == self.client_hello_handshake_packet

    def test_as_bytes_certificate_packet(self):
        record = Handshake.from_bytes(self.certificate_handshake_packet)
        assert record.as_bytes() == self.certificate_handshake_packet

    def test_as_bytes_certificate_request_packet(self):
        record = Handshake.from_bytes(self.certificate_request_handshake)
        assert record.as_bytes() == self.certificate_request_handshake

    def test_as_bytes_not_implemented(self):
        record = Handshake.from_bytes(self.server_key_exchange_handshake)
        assert record.as_bytes() == self.server_key_exchange_handshake

    def test_as_bytes_hello_request(self):
        record = Handshake.from_bytes(self.hello_request_handshake)
        assert record.as_bytes() == self.hello_request_handshake

    def test_as_bytes_server_hello_done(self):
        record = Handshake.from_bytes(self.server_hello_done_handshake)
        assert record.as_bytes() == self.server_hello_done_handshake

    def test_as_bytes_finished(self):
        record = Handshake.from_bytes(self.finished_handshake)
        assert record.as_bytes() == self.finished_handshake
