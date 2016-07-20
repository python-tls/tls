# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from tls._common import enums

from tls.alert_message import Alert


class TestAlert(object):

    def test_alert_parsing(self):
        packet = (
            b'\x02'
            b'\x16'
        )
        record = Alert.from_bytes(packet)
        assert record.level == enums.AlertLevel.FATAL
        assert record.description == enums.AlertDescription.RECORD_OVERFLOW
