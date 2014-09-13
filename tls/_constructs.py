from __future__ import absolute_import, division, print_function

from construct import Array, Bytes, Struct, UBInt16, UBInt32, UBInt8


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

Random = Struct(
    "random",
    UBInt32("gmt_unix_time"),
    Bytes("random_bytes", 28),
)

SessionID = Struct(
    "session_id",
    UBInt8("length"),
    Bytes("session_id", lambda ctx: ctx.length)
)

CipherSuites = Struct(
    "cipher_suites",
    UBInt16("length"),  # TODO: Reject packets of length 0
    Array(lambda ctx: ctx.length / 2, Bytes("cipher_suites", 2))
)

CompressionMethods = Struct(
    "compression_methods",
    UBInt8("length"),  # TODO: Reject packets of length 0
    Array(lambda ctx: ctx.length, UBInt8("compression_methods"))
)

Extension = Struct(
    "extensions",
    UBInt16("type"),
    UBInt16("length"),
    Bytes("data", lambda ctx: ctx.length),
)

ClientHello = Struct(
    "ClientHello",
    ProtocolVersion,
    Random,
    SessionID,
    CipherSuites,
    CompressionMethods,
    UBInt16("extensions_length"),
    Bytes("extensions_bytes", lambda ctx: ctx.extensions_length),
)

ServerHello = Struct(
    "ServerHello",
    ProtocolVersion,
    Random,
    SessionID,
    Bytes("cipher_suite", 2),
    UBInt8("compression_method"),
    UBInt16("extensions_length"),
    Bytes("extensions_bytes", lambda ctx: ctx.extensions_length),
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

PreMasterSecret = Struct(
    "pre_master_secret",
    ProtocolVersion,
    Bytes("random_bytes", 46),
)


CKEWithEncryptedPreMasterSecret = Struct(
    "ClientKeyExchange",
    UBInt16("length")
    Bytes("EncryptedPreMasterSecret", lambda ctx: ctx.length),
    # Because reasons: See "Implementation note" in
    # http://tools.ietf.org/html/rfc5246#section-7.4.7.1
)


