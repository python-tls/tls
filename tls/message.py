# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import attr

from construct import Container, ListContainer

from tls import _constructs

from tls._common import enums

from tls.hello_message import ClientHello, ProtocolVersion, ServerHello


class HelloRequest(object):
    """
    An object representing a HelloRequest struct.
    """
    def as_bytes(self):
        return b''


class ServerHelloDone(object):
    """
    An object representing a ServerHelloDone struct.
    """
    def as_bytes(self):
        return b''


@attr.s
class CertificateRequest(object):
    """
    An object representing a CertificateRequest struct.
    """
    certificate_types = attr.ib()
    supported_signature_algorithms = attr.ib()
    certificate_authorities = attr.ib()

    def as_bytes(self):
        return _constructs.CertificateRequest.build(Container(
            certificate_types=Container(
                length=len(self.certificate_types),
                certificate_types=[cert_type.value
                                   for cert_type in self.certificate_types]
            ),
            supported_signature_algorithms=ListContainer(
                Container(hash=algorithm.hash, signature=algorithm.signature)
                for algorithm in self.supported_signature_algorithms
            ),
            certificate_authorities=Container(
                length=len(self.certificate_authorities),
                certificate_authorities=self.certificate_authorities
            )
        ))

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``CertificateRequest`` struct.

        :param bytes: the bytes representing the input.
        :return: CertificateRequest object.
        """
        construct = _constructs.CertificateRequest.parse(bytes)
        return cls(
            certificate_types=[
                enums.ClientCertificateType(cert_type)
                for cert_type in construct.certificate_types.certificate_types
            ],
            supported_signature_algorithms=[
                SignatureAndHashAlgorithm(
                    hash=algorithm.hash,
                    signature=algorithm.signature,
                )
                for algorithm in (
                    construct.supported_signature_algorithms
                )
            ],
            certificate_authorities=(
                construct.certificate_authorities.certificate_authorities
            )
        )


@attr.s
class SignatureAndHashAlgorithm(object):
    """
    An object representing a SignatureAndHashAlgorithm struct.
    """
    hash = attr.ib()
    signature = attr.ib()


@attr.s
class ServerDHParams(object):
    """
    An object representing a ServerDHParams struct.
    """
    dh_p = attr.ib()
    dh_g = attr.ib()
    dh_Ys = attr.ib()

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``ServerDHParams`` struct.

        :param bytes: the bytes representing the input.
        :return: ServerDHParams object.
        """
        construct = _constructs.ServerDHParams.parse(bytes)
        return cls(
            dh_p=construct.dh_p,
            dh_g=construct.dh_g,
            dh_Ys=construct.dh_Ys
        )


@attr.s
class PreMasterSecret(object):
    """
    An object representing a PreMasterSecret struct.
    """
    client_version = attr.ib()
    random = attr.ib()

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``PreMasterSecret`` struct.

        :param bytes: the bytes representing the input.
        :return: CertificateRequest object.
        """
        construct = _constructs.PreMasterSecret.parse(bytes)
        return cls(
            client_version=ProtocolVersion(
                major=construct.version.major,
                minor=construct.version.minor,
            ),
            random=construct.random_bytes,
        )


@attr.s
class ASN1Cert(object):
    """
    An object representing ASN.1 Certificate
    """
    asn1_cert = attr.ib()

    def as_bytes(self):
        return _constructs.ASN1Cert.build(Container(
            length=len(self.asn1_cert),
            asn1_cert=self.asn1_cert
        ))


@attr.s
class Certificate(object):
    """
    An object representing a Certificate struct.
    """
    certificate_list = attr.ib()

    def as_bytes(self):
        return _constructs.Certificate.build(Container(
            certificate_list=[Container(asn1_cert=cert.asn1_cert)
                              for cert in self.certificate_list]
        ))

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``Certificate`` struct.

        :param bytes: the bytes representing the input.
        :return: Certificate object.
        """
        construct = _constructs.Certificate.parse(bytes)
        return cls(
            certificate_list=[
                ASN1Cert(
                    asn1_cert=asn1cert.asn1_cert
                )
                for asn1cert in construct.certificate_list],
        )


@attr.s
class URLAndHash(object):
    """
    An object representing a URLAndHash struct.
    """
    url = attr.ib()
    padding = attr.ib()
    sha1_hash = attr.ib()


@attr.s
class CertificateURL(object):
    """
    An object representing a CertificateURL struct.
    """
    type = attr.ib()
    url_and_hash_list = attr.ib()

    def as_bytes(self):
        return _constructs.CertificateURL.build(Container(
            type=self.type,
            url_and_hash_list=ListContainer(
                Container(
                    length=len(url_and_hash.url),
                    url=url_and_hash.url,
                    padding=url_and_hash.padding,
                    sha1_hash=url_and_hash.sha1_hash,
                )
                for url_and_hash in self.url_and_hash_list
            )
        ))

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``CertificateURL`` struct.

        :param bytes: the bytes representing the input.
        :return: CertificateURL object.
        """
        construct = _constructs.CertificateURL.parse(bytes)
        return cls(
            type=construct.type,
            url_and_hash_list=[
                URLAndHash(
                    url=url_and_hash.url,
                    padding=url_and_hash.padding,
                    sha1_hash=url_and_hash.sha1_hash,
                )
                for url_and_hash in construct.url_and_hash_list],
        )


@attr.s
class CertificateStatus(object):
    """
    An object representing a CertificateStatus struct
    """
    status_type = attr.ib()
    response = attr.ib()

    def as_bytes(self):
        return _constructs.CertificateStatus.build(Container(
            status_type=self.status_type,
            response=self.response,
        ))

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``CertificateStatus`` struct.

        :param bytes: bytes representing the input
        :return: CertificateStatus instance.
        """
        construct = _constructs.CertificateStatus.parse(bytes)

        return cls(
            status_type=construct.status_type,
            response=construct.response,
        )


@attr.s
class Finished(object):
    verify_data = attr.ib()

    def as_bytes(self):
        return self.verify_data


@attr.s
class Handshake(object):
    """
    An object representing a Handshake struct.
    """
    msg_type = attr.ib()
    length = attr.ib()
    body = attr.ib()

    def as_bytes(self):
        if self.msg_type in [
            # TODO: Make these a frozenset constant.
            enums.HandshakeType.SERVER_HELLO,
            enums.HandshakeType.CLIENT_HELLO,
            enums.HandshakeType.CERTIFICATE,
            enums.HandshakeType.CERTIFICATE_REQUEST,
            enums.HandshakeType.HELLO_REQUEST,
            enums.HandshakeType.SERVER_HELLO_DONE,
            enums.HandshakeType.FINISHED,
            enums.HandshakeType.CERTIFICATE_URL,
            enums.HandshakeType.CERTIFICATE_STATUS,
        ]:
            _body_as_bytes = self.body.as_bytes()
        else:
            _body_as_bytes = b''
        return _constructs.Handshake.build(
            Container(
                msg_type=self.msg_type.value,
                length=self.length,
                body=_body_as_bytes
            )
        )

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``Handshake`` struct.

        :param bytes: the bytes representing the input.
        :return: Handshake object.
        """
        construct = _constructs.Handshake.parse(bytes)
        return cls(
            msg_type=enums.HandshakeType(construct.msg_type),
            length=construct.length,
            body=cls._get_handshake_message(
                enums.HandshakeType(construct.msg_type), construct.body
            ),
        )

    @staticmethod
    def _get_handshake_message(msg_type, body):
        _handshake_message_parser = {
            enums.HandshakeType.CLIENT_HELLO: ClientHello.from_bytes,
            enums.HandshakeType.SERVER_HELLO: ServerHello.from_bytes,
            enums.HandshakeType.CERTIFICATE: Certificate.from_bytes,
            #    12: parse_server_key_exchange,
            enums.HandshakeType.CERTIFICATE_REQUEST:
                CertificateRequest.from_bytes,
            #    15: parse_certificate_verify,
            #    16: parse_client_key_exchange,
            enums.HandshakeType.CERTIFICATE_URL: CertificateURL.from_bytes,
            enums.HandshakeType.CERTIFICATE_STATUS:
                CertificateStatus.from_bytes,
        }

        try:
            if msg_type == enums.HandshakeType.HELLO_REQUEST:
                return HelloRequest()
            elif msg_type == enums.HandshakeType.SERVER_HELLO_DONE:
                return ServerHelloDone()
            elif msg_type == enums.HandshakeType.FINISHED:
                return Finished(verify_data=body)
            elif msg_type in [enums.HandshakeType.SERVER_KEY_EXCHANGE,
                              enums.HandshakeType.CERTIFICATE_VERIFY,
                              enums.HandshakeType.CLIENT_KEY_EXCHANGE]:
                raise NotImplementedError
            else:
                return _handshake_message_parser[msg_type](body)
        except NotImplementedError:
            return None     # TODO
