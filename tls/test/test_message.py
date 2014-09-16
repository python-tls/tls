from __future__ import absolute_import, division, print_function

from tls.hello_message import ProtocolVersion

from tls.message import (
    ClientCertificateType, HashAlgorithm, PreMasterSecret, SignatureAlgorithm,
    parse_certificate_request, parse_pre_master_secret
)


class TestCertificateRequestParsing(object):
    """
    Tests for parsing of CertificateRequest messages.
    """

    def test_parse_certificate_request(self):
        packet = (
            b'\x01'  # certificate_types length
            b'\x01'  # certificate_types
            b'\x00\x02'  # supported_signature_algorithms length
            b'\x01'  # supported_signature_algorithms.hash
            b'\x01'  # supported_signature_algorithms.signature
            b'\x00\x00'  # certificate_authorities length
            b''  # certificate_authorities
        )
        record = parse_certificate_request(packet)
        assert record.certificate_types == [ClientCertificateType.RSA_SIGN]
        assert len(record.supported_signature_algorithms) == 1
        assert record.supported_signature_algorithms[0].hash == \
            HashAlgorithm.MD5
        assert record.supported_signature_algorithms[0].signature == \
            SignatureAlgorithm.RSA
        assert record.certificate_authorities == b''

    def test_parse_certificate_request_with_authorities(self):
        packet = (
            b'\x01'  # certificate_types length
            b'\x01'  # certificate_types
            b'\x00\x02'  # supported_signature_algorithms length
            b'\x01'  # supported_signature_algorithms.hash
            b'\x01'  # supported_signature_algorithms.signature
            b'\x00\x02'  # certificate_authorities length
            b'03'  # certificate_authorities
        )
        record = parse_certificate_request(packet)
        assert record.certificate_authorities == b'03'


class TestPreMasterSecretParsing(object):
    """
    Tests for parsing of PreMasterSecret struct.
    """

    def test_parse_pre_master_secret(self):
        import os
        r = os.urandom(46)
        packet = (
            b'\x03\x00'  # ClientHello.client_version
            + r
        )
        record = parse_pre_master_secret(packet)
        assert isinstance(record, PreMasterSecret)
        assert isinstance(record.client_version, ProtocolVersion)
        assert record.client_version.major == 3
        assert record.client_version.minor == 0
        assert record.random == r
