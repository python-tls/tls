# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import attr

from construct import Container

from tls import _constructs

from tls._common import enums


@attr.s
class ProtocolVersion(object):
    """
    An object representing a ProtocolVersion struct.
    """
    major = attr.ib()
    minor = attr.ib()


@attr.s
class TLSPlaintext(object):
    """
    An object representing a TLSPlaintext struct.
    """
    type = attr.ib()
    version = attr.ib()
    fragment = attr.ib()

    def as_bytes(self):
        return _constructs.TLSPlaintext.build(
            Container(
                type=self.type.value,
                version=Container(major=self.version.major,
                                  minor=self.version.minor),
                length=len(self.fragment),
                fragment=self.fragment
            )
        )

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``TLSPlaintext`` struct.

        :param bytes: the bytes representing the input.
        :return: TLSPlaintext object.
        """
        construct = _constructs.TLSPlaintext.parse(bytes)
        return cls(
            type=enums.ContentType(construct.type),
            version=ProtocolVersion(
                major=construct.version.major,
                minor=construct.version.minor
            ),
            fragment=construct.fragment
        )


@attr.s
class TLSCompressed(object):
    """
    An object representing a TLSCompressed struct.
    """
    type = attr.ib()
    version = attr.ib()
    fragment = attr.ib()

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``TLSCompressed`` struct.

        :param bytes: the bytes representing the input.
        :return: TLSCompressed object.
        """
        construct = _constructs.TLSCompressed.parse(bytes)
        return cls(
            type=enums.ContentType(construct.type),
            version=ProtocolVersion(
                major=construct.version.major,
                minor=construct.version.minor
            ),
            fragment=construct.fragment
        )


@attr.s
class TLSCiphertext(object):
    """
    An object representing a TLSCiphertext struct.
    """
    type = attr.ib()
    version = attr.ib()
    fragment = attr.ib()

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse a ``TLSCiphertext`` struct.

        :param bytes: the bytes representing the input.
        :return: TLSCiphertext object.
        """
        construct = _constructs.TLSCiphertext.parse(bytes)
        return cls(
            type=enums.ContentType(construct.type),
            version=ProtocolVersion(
                major=construct.version.major,
                minor=construct.version.minor
            ),
            fragment=construct.fragment
        )
