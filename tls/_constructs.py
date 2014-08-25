from __future__ import absolute_import, division, print_function

from construct import Bytes, Struct, UBInt16, UBInt8


ProtocolVersion = Struct(
    "version",
    UBInt8("major"),
    UBInt8("minor")
)

TLSPlaintext = Struct(
    "TLSPlaintext",
    UBInt8("type"),
    ProtocolVersion,
    UBInt16("length"),  # TODO: Reject packets with length > 2 ** 14
    Bytes("fragment", lambda ctx: ctx.length),
)

TLSCompressed = Struct(
    "TLSCompressed",
    UBInt8("type"),
    ProtocolVersion,
    UBInt16("length"),  # TODO: Reject packets with length > 2 ** 14 + 1024
    Bytes("fragment", lambda ctx: ctx.length),
)

TLSCiphertext = Struct(
    "TLSCiphertext",
    UBInt8("type"),
    ProtocolVersion,
    UBInt16("length"),  # TODO: Reject packets with length > 2 ** 14 + 2048
    Bytes("fragment", lambda ctx: ctx.length),
)

SignatureAndHashAlgorithm = Struct(
    "supported_signature_algorithms",
    UBInt8("hash"),
    UBInt8("signature"),
)

DistinguishedName = Bytes("certificate_authorities", 65535)

CertificateRequest = Struct(
    "CertificateRequest",
    UBInt8("certificate_types"),  # XXX: I think this is a list or something. Check.
    SignatureAndHashAlgorithm,
    DistinguishedName,
)
