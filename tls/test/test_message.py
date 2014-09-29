from __future__ import absolute_import, division, print_function

from tls.message import (
    ClientCertificateType, HashAlgorithm, SignatureAlgorithm,
    parse_certificate_request, parse_server_dh_params
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
        record = parse_server_dh_params(packet)
        assert record.dh_p == b'123'
        assert record.dh_g == b'5678'
        assert record.dh_Ys == b'78'
