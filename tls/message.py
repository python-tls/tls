from __future__ import absolute_import, division, print_function

from enum import Enum

from characteristic import attributes

from construct import Container

from six import BytesIO

from tls import _constructs

from tls.hello_message import (
    ProtocolVersion, parse_client_hello, parse_server_hello
)


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


class HandshakeType(Enum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20


class HelloRequest(object):
    """
    An object representing a HelloRequest struct.
    """


class ServerHelloDone(object):
    """
    An object representing a ServerHelloDone struct.
    """


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


@attributes(['asn1_cert'])
class ASN1Cert(object):
    """
    An object representing ASN.1 Certificate
    """


@attributes(['certificate_list'])
class Certificate(object):
    """
    An object representing a Certificate struct.
    """
    def as_bytes(self):
        return _constructs.Certificate.build(
            certificates_length=sum([4 + len(asn1cert.asn1_cert)
                                     for asn1cert in self.certificate_list]),
            certificates_bytes=b''.join(
                [asn1cert.as_bytes() for asn1cert in self.certificate_list]
            )
        )


@attributes(['msg_type', 'length', 'body'])
class Handshake(object):
    """
    An object representing a Handshake struct.
    """
    def as_bytes(self):
        if self.msg_type.value in [1, 2]:
            _body_as_bytes = self.body.as_bytes()
        else:
            _body_as_bytes = None
        return _constructs.Handshake.build(
            Container(
                msg_type=self.msg_type.value,
                length=self.length,
                body=_body_as_bytes
            )
        )



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
        certificates.append(
            ASN1Cert(asn1_cert=certificate_construct.asn1_cert)
        )
    return Certificate(
        certificate_list=certificates
    )


_handshake_message_parser = {
    1: parse_client_hello,
    2: parse_server_hello,
    11: parse_certificate,
    #    12: parse_server_key_exchange,
    13: parse_certificate_request,
    #    15: parse_certificate_verify,
    #    16: parse_client_key_exchange,
    #    20: parse_finished,
}


def _get_handshake_message(msg_type, body):
    try:
        if msg_type == 0:
            return HelloRequest()
        elif msg_type == 14:
            return ServerHelloDone()
        elif msg_type in [12, 15, 16, 20]:
            raise NotImplementedError
        else:
            return _handshake_message_parser[msg_type](body)
    except NotImplementedError:
        return None     # TODO


def parse_handshake_struct(bytes):
    """
    Parse a ``Handshake`` struct.

    :param bytes: the bytes representing the input.
    :return: Handshake object.
    """
    construct = _constructs.Handshake.parse(bytes)
    return Handshake(
        msg_type=HandshakeType(construct.msg_type),
        length=construct.length,
        body=_get_handshake_message(construct.msg_type, construct.body),
    )
