# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.hazmat.primitives import hashes

from hypothesis import HealthCheck, given, settings, strategies as st

import pytest

from tls._common.prf import prf

from tls.test._common import hypothesis_test


class TestPRFVectors(object):
    """
    Test against the test vectors in
    https://www.ietf.org/mail-archive/web/tls/current/msg03416.html
    """

    def test_sha224_88bytes(self):
        """
        Generate 88 bytes of pseudo-randomness using TLS1.2PRF-SHA224
        """
        secret = (
            b'\xe1\x88\x28\x74\x03\x52\xb5\x30'
            b'\xd6\x9b\x34\xc6\x59\x7d\xea\x2e'
        )
        seed = (
            b'\xf5\xa3\xfe\x6d\x34\xe2\xe2\x85'
            b'\x60\xfd\xca\xf6\x82\x3f\x90\x91'
        )
        label = b'test label'

        expected_output = (
            b'\x22\x4d\x8a\xf3\xc0\x45\x33\x93'
            b'\xa9\x77\x97\x89\xd2\x1c\xf7\xda'
            b'\x5e\xe6\x2a\xe6\xb6\x17\x87\x3d'
            b'\x48\x94\x28\xef\xc8\xdd\x58\xd1'
            b'\x56\x6e\x70\x29\xe2\xca\x3a\x5e'
            b'\xcd\x35\x5d\xc6\x4d\x4d\x92\x7e'
            b'\x2f\xbd\x78\xc4\x23\x3e\x86\x04'
            b'\xb1\x47\x49\xa7\x7a\x92\xa7\x0f'
            b'\xdd\xf6\x14\xbc\x0d\xf6\x23\xd7'
            b'\x98\x60\x4e\x4c\xa5\x51\x27\x94'
            b'\xd8\x02\xa2\x58\xe8\x2f\x86\xcf'
        )
        actual_output = prf(secret, label, seed, hashes.SHA224(), 88)
        assert actual_output == expected_output

    def test_sha256_100bytes(self):
        """
        Generate 100 bytes of pseudo-randomness using TLS1.2PRF-SHA256
        """
        secret = (
            b'\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35'
        )
        seed = (
            b'\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c'
        )
        label = b'test label'
        expected_output = (
            b'\xe3\xf2\x29\xba\x72\x7b\xe1\x7b'
            b'\x8d\x12\x26\x20\x55\x7c\xd4\x53'
            b'\xc2\xaa\xb2\x1d\x07\xc3\xd4\x95'
            b'\x32\x9b\x52\xd4\xe6\x1e\xdb\x5a'
            b'\x6b\x30\x17\x91\xe9\x0d\x35\xc9'
            b'\xc9\xa4\x6b\x4e\x14\xba\xf9\xaf'
            b'\x0f\xa0\x22\xf7\x07\x7d\xef\x17'
            b'\xab\xfd\x37\x97\xc0\x56\x4b\xab'
            b'\x4f\xbc\x91\x66\x6e\x9d\xef\x9b'
            b'\x97\xfc\xe3\x4f\x79\x67\x89\xba'
            b'\xa4\x80\x82\xd1\x22\xee\x42\xc5'
            b'\xa7\x2e\x5a\x51\x10\xff\xf7\x01'
            b'\x87\x34\x7b\x66'
        )
        actual_output = prf(secret, label, seed, hashes.SHA256(), 100)
        assert actual_output == expected_output

    def test_sha512_196bytes(self):
        """
        Generate 196 bytes of pseudo-randomness using TLS1.2PRF-SHA512
        """
        secret = (
            b'\xb0\x32\x35\x23\xc1\x85\x35\x99'
            b'\x58\x4d\x88\x56\x8b\xbb\x05\xeb'
        )

        seed = (
            b'\xd4\x64\x0e\x12\xe4\xbc\xdb\xfb'
            b'\x43\x7f\x03\xe6\xae\x41\x8e\xe5'
        )

        label = b'test label'

        expected_output = (
            b'\x12\x61\xf5\x88\xc7\x98\xc5\xc2'
            b'\x01\xff\x03\x6e\x7a\x9c\xb5\xed'
            b'\xcd\x7f\xe3\xf9\x4c\x66\x9a\x12'
            b'\x2a\x46\x38\xd7\xd5\x08\xb2\x83'
            b'\x04\x2d\xf6\x78\x98\x75\xc7\x14'
            b'\x7e\x90\x6d\x86\x8b\xc7\x5c\x45'
            b'\xe2\x0e\xb4\x0c\x1c\xf4\xa1\x71'
            b'\x3b\x27\x37\x1f\x68\x43\x25\x92'
            b'\xf7\xdc\x8e\xa8\xef\x22\x3e\x12'
            b'\xea\x85\x07\x84\x13\x11\xbf\x68'
            b'\x65\x3d\x0c\xfc\x40\x56\xd8\x11'
            b'\xf0\x25\xc4\x5d\xdf\xa6\xe6\xfe'
            b'\xc7\x02\xf0\x54\xb4\x09\xd6\xf2'
            b'\x8d\xd0\xa3\x23\x3e\x49\x8d\xa4'
            b'\x1a\x3e\x75\xc5\x63\x0e\xed\xbe'
            b'\x22\xfe\x25\x4e\x33\xa1\xb0\xe9'
            b'\xf6\xb9\x82\x66\x75\xbe\xc7\xd0'
            b'\x1a\x84\x56\x58\xdc\x9c\x39\x75'
            b'\x45\x40\x1d\x40\xb9\xf4\x6c\x7a'
            b'\x40\x0e\xe1\xb8\xf8\x1c\xa0\xa6'
            b'\x0d\x1a\x39\x7a\x10\x28\xbf\xf5'
            b'\xd2\xef\x50\x66\x12\x68\x42\xfb'
            b'\x8d\xa4\x19\x76\x32\xbd\xb5\x4f'
            b'\xf6\x63\x3f\x86\xbb\xc8\x36\xe6'
            b'\x40\xd4\xd8\x98'
        )
        actual_output = prf(secret, label, seed, hashes.SHA512(), 196)
        assert actual_output == expected_output

    def test_sha384_148bytes(self):
        """
        Generate 148 bytes of pseudo-randomness using TLS1.2PRF-SHA384
        """
        secret = (
            b'\xb8\x0b\x73\x3d\x6c\xee\xfc\xdc'
            b'\x71\x56\x6e\xa4\x8e\x55\x67\xdf'
        )

        seed = (
            b'\xcd\x66\x5c\xf6\xa8\x44\x7d\xd6'
            b'\xff\x8b\x27\x55\x5e\xdb\x74\x65'
        )
        label = b'test label'
        expected_output = (
            b'\x7b\x0c\x18\xe9\xce\xd4\x10\xed'
            b'\x18\x04\xf2\xcf\xa3\x4a\x33\x6a'
            b'\x1c\x14\xdf\xfb\x49\x00\xbb\x5f'
            b'\xd7\x94\x21\x07\xe8\x1c\x83\xcd'
            b'\xe9\xca\x0f\xaa\x60\xbe\x9f\xe3'
            b'\x4f\x82\xb1\x23\x3c\x91\x46\xa0'
            b'\xe5\x34\xcb\x40\x0f\xed\x27\x00'
            b'\x88\x4f\x9d\xc2\x36\xf8\x0e\xdd'
            b'\x8b\xfa\x96\x11\x44\xc9\xe8\xd7'
            b'\x92\xec\xa7\x22\xa7\xb3\x2f\xc3'
            b'\xd4\x16\xd4\x73\xeb\xc2\xc5\xfd'
            b'\x4a\xbf\xda\xd0\x5d\x91\x84\x25'
            b'\x9b\x5b\xf8\xcd\x4d\x90\xfa\x0d'
            b'\x31\xe2\xde\xc4\x79\xe4\xf1\xa2'
            b'\x60\x66\xf2\xee\xa9\xa6\x92\x36'
            b'\xa3\xe5\x26\x55\xc9\xe9\xae\xe6'
            b'\x91\xc8\xf3\xa2\x68\x54\x30\x8d'
            b'\x5e\xaa\x3b\xe8\x5e\x09\x90\x70'
            b'\x3d\x73\xe5\x6f'
        )
        actual_output = prf(secret, label, seed, hashes.SHA384(), 148)
        assert actual_output == expected_output


def ascii_bytes(min_size, max_size):
    """
    A Hypothesis strategy that returns ASCII bytes.

    :return: :py:class:`bytes`
    """
    ascii_char = st.integers(min_value=0, max_value=127)
    # convert the list to a bytearray first, because bytearray's
    # constructor takes an iterable of integers on both Python 2 and
    # Python 3
    return st.lists(elements=ascii_char,
                    min_size=min_size,
                    max_size=max_size).map(bytearray).map(bytes)


def prf_given():
    """
    A wrapper for :py:func:`hypothesis.given` that establishes
    parameters common to all Pseudo-Random Function tests.

    :return: The same opaque type returned by
             :py:func:`hypothesis.given`
    """
    _prf_given = given(secret=st.binary(max_size=4096),
                       label=ascii_bytes(min_size=1, max_size=1024),
                       # OpenSSL does not use seeds longer than 1024 bytes
                       seed=st.binary(max_size=1024),
                       hash_cls=st.sampled_from([
                           hashes.SHA1,
                           hashes.SHA224,
                           hashes.SHA256,
                           hashes.SHA384,
                           hashes.SHA512,
                           hashes.RIPEMD160,
                           hashes.Whirlpool,
                           hashes.MD5,
                       ]),
                       output_length=st.integers(min_value=0, max_value=1024))

    def _ignore_slow_and_large_prf_given(function):
        """
        Suppress data generation and size speed checks.
        """
        ignore_slow = settings(suppress_health_check=[
            HealthCheck.data_too_large,
            HealthCheck.too_slow,
        ])
        return ignore_slow(_prf_given(function))

    return _ignore_slow_and_large_prf_given


@hypothesis_test
class TestPRF(object):
    """
    Hypothesis tests for the Pseudo-random function
    (:py:func:`tls._common.prf.prf`).
    """

    @pytest.fixture(scope="class")
    def generated_with_params(self):
        """
        A class-scoped dictionary fixture for mapping PRF inputs to
        outputs.

        :return: :py:class:`dict`, for use in
                 :py:meth:`tests.hypothesis.TestPRF.test_unique`
        """
        return {}

    @prf_given()
    def test_length_returned(self,
                             secret,
                             label,
                             seed,
                             hash_cls,
                             output_length):
        """
        The output of :py:func:`tls._common.prf.prf` is exactly as long
        as requested.
        """
        generated = prf(secret, label, seed, hash_cls(), output_length)
        assert len(generated) == output_length

    @prf_given()
    def test_unique(self,
                    secret,
                    label,
                    seed,
                    hash_cls,
                    output_length,
                    generated_with_params):
        """
        No two inputs to :py:func:`tls._common.prf.prf` result in the
        same output.
        """
        params = (secret, label, seed, hash_cls, output_length)
        generated = prf(secret, label, seed, hash_cls(), output_length)
        previously_generated = generated_with_params.get(params)
        assert (previously_generated is None or
                generated == previously_generated)
        generated_with_params[params] = generated
