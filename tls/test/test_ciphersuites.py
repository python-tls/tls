# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from tls.ciphersuites import CipherSuites


def test_ciphersuites():
    # TODO: This is to fulfill test coverage. Either make more useful later or
    # remove once the CipherSuites enum gets used in other places.
    assert CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256.value == 0x006B
