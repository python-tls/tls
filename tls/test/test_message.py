from __future__ import absolute_import, division, print_function

from tls.message import (
    ClientCertificateType, HashAlgorithm, SignatureAlgorithm,
    parse_certificate_request
)


class TestCertificateRequestParsing(object):
    """
    Tests for parsing of CertificateRequest messages.
    """

    def test_parse_certificate_request(self):
        packet = (
            b'\x01'  # certificate_types
            b'\x01'  # supported_signature_algorithms.hash
            b'\x01'  # supported_signature_algorithms.signature
            b''  # certificate_authorities
        )
        record = parse_certificate_request(packet)
        assert record.certificate_types == ClientCertificateType.RSA_SIGN
        assert record.supported_signature_algorithms.hash == HashAlgorithm.MD5
        assert record.supported_signature_algorithms.signature == \
            SignatureAlgorithm.RSA
        assert record.certificate_authorities == []
