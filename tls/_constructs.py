from construct import Bytes, Struct, UBInt16, UBInt8


ProtocolVersion = Struct(
    "version",
    UBInt8("major"),
    UBInt8("minor"))

TLSPlaintext = Struct(
    "TLSPlaintext",
    UBInt8("type"),
    ProtocolVersion,
    UBInt16("length"),
    Bytes("fragment", lambda ctx: ctx.length),
    )
