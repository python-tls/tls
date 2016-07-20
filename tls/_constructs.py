# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from functools import partial

from construct import Array, Bytes, Struct, UBInt16, UBInt32, UBInt8

from tls._common._constructs import (EnumClass, PrefixedBytes, SizeAtLeast,
                                     SizeAtMost, SizeWithin, TLSPrefixedArray,
                                     UBInt24)

from tls.ciphersuites import CipherSuites


ProtocolVersion = Struct(
    "version",
    UBInt8("major"),
    UBInt8("minor"),
)

TLSPlaintext = Struct(
    "TLSPlaintext",
    UBInt8("type"),
    ProtocolVersion,
    PrefixedBytes("fragment",
                  SizeAtMost(UBInt16("length"),
                             max_size=2 ** 14)),
)

TLSCompressed = Struct(
    "TLSCompressed",
    UBInt8("type"),
    ProtocolVersion,
    PrefixedBytes("fragment",
                  SizeAtMost(UBInt16("length"),
                             max_size=2 ** 14 + 1024)),
)

TLSCiphertext = Struct(
    "TLSCiphertext",
    UBInt8("type"),
    ProtocolVersion,
    PrefixedBytes("fragment",
                  SizeAtMost(UBInt16("length"),
                             max_size=2 ** 14 + 2048)),
)

Random = Struct(
    "random",
    UBInt32("gmt_unix_time"),
    Bytes("random_bytes", 28),
)

SessionID = Struct(
    "session_id",
    PrefixedBytes("session_id"),
)


CompressionMethods = Struct(
    "compression_methods",
    SizeAtLeast(UBInt8("length"), min_size=1),
    Array(lambda ctx: ctx.length, UBInt8("compression_methods"))
)

Extension = Struct(
    "extensions",
    UBInt16("type"),
    PrefixedBytes("data", UBInt16("length")),
)

ClientHello = Struct(
    "ClientHello",
    ProtocolVersion,
    Random,
    SessionID,
    TLSPrefixedArray(EnumClass(UBInt8("cipher_suites"),
                               CipherSuites),
                     length_validator=partial(SizeAtLeast, min_size=1)),
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
    SizeAtLeast(UBInt8("length"), min_size=1),
    Array(lambda ctx: ctx.length, UBInt8("certificate_types")),
)

SignatureAndHashAlgorithm = Struct(
    "algorithms",
    UBInt8("hash"),
    UBInt8("signature"),
)

SupportedSignatureAlgorithms = Struct(
    "supported_signature_algorithms",
    SizeAtLeast(UBInt16("supported_signature_algorithms_length"),
                min_size=1),
    Array(
        lambda ctx: ctx.supported_signature_algorithms_length / 2,
        SignatureAndHashAlgorithm,
    ),
)

DistinguishedName = Struct(
    "certificate_authorities",
    UBInt16("length"),
    Bytes("certificate_authorities", lambda ctx: ctx.length),
)

CertificateRequest = Struct(
    "CertificateRequest",
    ClientCertificateType,
    SupportedSignatureAlgorithms,
    DistinguishedName,
)

ServerDHParams = Struct(
    "ServerDHParams",
    PrefixedBytes("dh_p", UBInt16("dh_p_length")),
    PrefixedBytes("dh_g", UBInt16("dh_g_length")),
    PrefixedBytes("dh_Ys", UBInt16("dh_Ys_length")),
)

PreMasterSecret = Struct(
    "pre_master_secret",
    ProtocolVersion,
    Bytes("random_bytes", 46),
)

ASN1Cert = Struct(
    "ASN1Cert",
    SizeWithin(UBInt32("length"),
               min_size=1, max_size=2 ** 24 - 1),
    Bytes("asn1_cert", lambda ctx: ctx.length),
)

Certificate = Struct(
    "Certificate",
    SizeWithin(UBInt32("certificates_length"),
               min_size=1, max_size=2 ** 24 - 1),
    Bytes("certificates_bytes", lambda ctx: ctx.certificates_length),
)

Handshake = Struct(
    "Handshake",
    UBInt8("msg_type"),
    UBInt24("length"),
    Bytes("body", lambda ctx: ctx.length),
)

Alert = Struct(
    "Alert",
    UBInt8("level"),
    UBInt8("description"),
)
