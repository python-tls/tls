from __future__ import absolute_import, division, print_function

from enum import Enum

from characteristic import attributes

from tls import _constructs

from tls.hello_message import ProtocolVersion


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


@attributes(['client_version', 'random'])
class PreMasterSecret(object):
    """
    An object representing a PreMasterSecret struct.
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


def parse_pre_master_secret(bytes):
    """
    Parse a ``PreMasterSecret`` struct.

    :param bytes: the bytes representing the input.
    :return: CertificateRequest object.
    """
    construct = _constructs.PreMasterSecret.parse(bytes)
    return PreMasterSecret(
        client_version=ProtocolVersion(
            major=construct.version.major,
            minor=construct.version.minor,
        ),
        random=construct.random_bytes,
    )
