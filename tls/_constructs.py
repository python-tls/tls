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
    "TLSCompressed",
    UBInt8("type"),
    ProtocolVersion,
    UBInt16("length"),  # TODO: Reject packets with length > 2 ** 14 + 2048
    Bytes("fragment", lambda ctx: ctx.length),
)

# HelloRequest = Struct(
#    "HelloRequest"
# )

ClientVersion = Struct(
    "client_version",
    UBInt8("major"),
    UBInt8("minor")
)


Random = Struct(
    "random",
    UBInt32("gmt_unix_time"),
    Bytes("random_bytes", 28),
)


SessionID = Bytes("session_id", 32)


CipherSuite = Array(2, UBInt8("cipher_suites"))


Extension = Struct(
    "extensions",
    UBInt16("extension_type"),
    Bytes("extension_data", 1),
    # TODO: Make this <0 - 65535>
)


ClientHello = Struct(
    "ClientHello",
    ClientVersion,
    Random,
    SessionID,
    CipherSuite,
    UBInt8("compression_methods"),
    Extension,
)
