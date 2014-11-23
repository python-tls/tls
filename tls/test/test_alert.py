# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from tls.alert_message import AlertDescription, AlertLevel, parse_alert


class TestAlert(object):

    def test_alert_parsing(self):
        packet = (
            b'\x02'
            b'\x16'
        )
        record = parse_alert(packet)
        assert record.level == AlertLevel.FATAL
        assert record.description == AlertDescription.RECORD_OVERFLOW
