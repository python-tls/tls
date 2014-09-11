from __future__ import absolute_import, division, print_function

from construct import Array, Bytes, Struct, UBInt16, UBInt8


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

ClientCertificateType = Struct(
    "certificate_types",
    UBInt8("length"),  # TODO: Reject packets of length 0
    Array(lambda ctx: ctx.length, UBInt8("certificate_types")),
)

SignatureAndHashAlgorithm = Struct(
    "algorithms",
    UBInt8("hash"),
    UBInt8("signature"),
)

SupportedSignatureAlgorithms = Struct(
    "supported_signature_algorithms",
    UBInt16("supported_signature_algorithms_length"),
    # TODO: Reject packets of length 0
    Array(
        lambda ctx: ctx.supported_signature_algorithms_length / 2,
        SignatureAndHashAlgorithm,
    ),
)

DistinguishedName = Struct(
    "certificate_authorities",
    UBInt16("length"),
    Bytes("certificate_authorities", lambda ctx: ctx.length)
)

CertificateRequest = Struct(
    "CertificateRequest",
    ClientCertificateType,
    SupportedSignatureAlgorithms,
    DistinguishedName,
)
