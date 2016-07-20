# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import attr

from tls import _constructs

from tls._common import enums


@attr.s
class Alert(object):
    """
    An object representing an Alert message.
    """
    level = attr.ib()
    description = attr.ib()

    @classmethod
    def from_bytes(cls, bytes):
        """
        Parse an ``Alert`` struct.

        :param bytes: the bytes representing the input.
        :return: Alert object.
        """
        construct = _constructs.Alert.parse(bytes)
        return cls(
            level=enums.AlertLevel(construct.level),
            description=enums.AlertDescription(construct.description)
        )
