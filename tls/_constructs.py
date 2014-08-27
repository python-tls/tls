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

SignatureAndHashAlgorithm = Struct(
    "supported_signature_algorithms",
    UBInt8("hash"),
    UBInt8("signature"),
)

# XXX: A list of the distinguished names [X501] of acceptable
#      certificate_authorities, represented in DER-encoded format.  These
#      distinguished names may specify a desired distinguished name for a
#      root CA or for a subordinate CA; thus, this message can be used to
#      describe known roots as well as a desired authorization space.  If
#      the certificate_authorities list is empty, then the client MAY
#      send any certificate of the appropriate ClientCertificateType,
#      unless there is some external arrangement to the contrary.

# TODO: An empty list for now.

DistinguishedName = Array(0, UBInt8("certificate_authorities"))

CertificateRequest = Struct(
    "CertificateRequest",
    UBInt8("certificate_types"),  # TODO: Maybe a list of variable length.
    SignatureAndHashAlgorithm,
    DistinguishedName,
)
