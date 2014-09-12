from __future__ import absolute_import, division, print_function

from tls.message import (
    Certificate, ClientCertificateType, HashAlgorithm, SignatureAlgorithm,
    parse_certificate, parse_certificate_request
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


class TestCertificateParsing(object):
    """
    Tests for parsing of Certificate messages.
    """

    def test_parse_certificate(self):
        packet = (
            b'\x00\x00\x00\x07'  # certificate_length
            b'\x00\x00\x00\x03'  # certificate.certificate_list.asn1_cert length
            b'ABC'  # certificate.certificate_list.asn1_cert
        )
        record = parse_certificate(packet)
        assert isinstance(record, Certificate)
        assert record.certificate_list == [b'ABC']
