# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pytest

from tls.ciphersuites import CipherSuites, select_preferred_ciphersuite
from tls.exceptions import UnsupportedCipherException


def test_ciphersuites():
    # TODO: This is to fulfill test coverage. Either make more useful later or
    # remove once the CipherSuites enum gets used in other places.
    assert CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256.value == 0x006B


def test_select_preferred_ciphersuite():
    assert select_preferred_ciphersuite([
        CipherSuites.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
        CipherSuites.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
    ], [
        CipherSuites.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
        CipherSuites.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
    ]) == CipherSuites.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5


def test_unsupported_ciphersuite():
    with pytest.raises(UnsupportedCipherException):
        select_preferred_ciphersuite([
            CipherSuites.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
        ], [
            CipherSuites.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
        ])
