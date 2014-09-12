from __future__ import absolute_import, division, print_function

from enum import Enum

from characteristic import attributes

from six import BytesIO

from tls import _constructs


class ClientCertificateType(Enum):
    RSA_SIGN = 1
    DSS_SIGN = 2
    RSA_FIXED_DH = 3
    DSS_FIXED_DH = 4
    RSA_EPHEMERAL_DH_RESERVED = 5
    DSS_EPHEMERAL_DH_RESERVED = 6
    FORTEZZA_DMS_RESERVED = 20


class HashAlgorithm(Enum):
    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6


class SignatureAlgorithm(Enum):
    ANONYMOUS = 0
    RSA = 1
    DSA = 2
    ECDSA = 3


@attributes(['certificate_types', 'supported_signature_algorithms',
             'certificate_authorities'])
class CertificateRequest(object):
    """
    An object representing a CertificateRequest struct.
    """


@attributes(['hash', 'signature'])
class SignatureAndHashAlgorithm(object):
    """
    An object representing a SignatureAndHashAlgorithm struct.
    """


@attributes(['certificate_list'])
class Certificate(object):
    """
    An object representing a Certificate struct.
    """

def parse_certificate_request(bytes):
    """
    Parse a ``CertificateRequest`` struct.

    :param bytes: the bytes representing the input.
    :return: CertificateRequest object.
    """
    construct = _constructs.CertificateRequest.parse(bytes)
    return CertificateRequest(
        certificate_types=[
            ClientCertificateType(cert_type)
            for cert_type in construct.certificate_types.certificate_types
        ],
        supported_signature_algorithms=[
            SignatureAndHashAlgorithm(
                hash=HashAlgorithm(algorithm.hash),
                signature=SignatureAlgorithm(algorithm.signature),
            )
            for algorithm in (
                construct.supported_signature_algorithms.algorithms
            )
        ],
        certificate_authorities=(
            construct.certificate_authorities.certificate_authorities
        )
    )

def parse_certificate(bytes):
    """
    Parse a ``Certificate`` struct.

    :param bytes: the bytes representing the input.
    :return: Certificate object.
    """
    construct = _constructs.Certificate.parse(bytes)
    # XXX: Find a better way to parse an array of variable-length objects
    certificates = []
    certificates_io = BytesIO(construct.certificates_bytes)

    while certificates_io.tell() < construct.certificates_length:
        certificate_construct = _constructs.ASN1Cert.parse_stream(
            certificates_io
        )
        certificates.append(certificate_construct.asn1_cert)
    return Certificate(
        certificate_list=certificates
    )
