# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import enum

from construct import Struct, UBInt16, UBInt8
from construct.adapters import MappingError, ValidationError, Validator
from construct.core import AdaptationError, Construct, Container

import pytest

from tls.utils import (BytesAdapter, EnumClass, EnumSwitch,
                       PrefixedBytes, SizeAtLeast, SizeAtMost,
                       SizeWithin, TLSPrefixedArray, UBInt24,
                       _UBInt24)


@pytest.mark.parametrize("byte,number", [
    (b"\x00\x00\xFF", 255),
    (b"\x00\xFF\xFF", 65535),
    (b"\xFF\xFF\xFF", 16777215)
])
class TestUBInt24(object):
    def test_encode(self, byte, number):
        ubint24 = _UBInt24(Construct(name="test"))
        assert ubint24._encode(number, context=object()) == byte

    def test_decode(self, byte, number):
        ubint24 = _UBInt24(Construct(name="test"))
        assert ubint24._decode(byte, context=object()) == number


def test_ubint24():
    assert isinstance(UBInt24("test"), _UBInt24)


class TestBytesAdapter(object):
    """
    Tests for :py:class:`tls.utils.BytesAdapter`.
    """

    @pytest.fixture
    def bytes_adapted(self):
        """
        A :py:class:`tls.utils.BytesAdapter` that adapts a trivial
        :py:func:`construct.Construct`.
        """
        return BytesAdapter(Construct(name=None))

    @pytest.mark.parametrize("non_bytes", [
        u"invalid",
        u"\u2022",
        object(),
    ])
    def test_encode_disallows_non_bytes(self, bytes_adapted, non_bytes):
        """
        :py:meth:`tls.utils.BytesAdapter._encode` raises a
        :py:exc:`construct.core.AdaptationError` when encoding
        anything that isn't :py:class:`bytes`.
        """
        with pytest.raises(AdaptationError) as e:
            bytes_adapted._encode(non_bytes, context=object())

        assert 'requires bytes' in e.value.args[0]

    @pytest.mark.parametrize("byte_string", [
        b"valid",
        b"\xff",
    ])
    def test_encode_allows_bytes(self, bytes_adapted, byte_string):
        """
        :py:meth:`tls.utils.BytesAdapter._encode` encodes
        :py:class:`bytes` without raising an exception.
        """
        assert bytes_adapted._encode(byte_string,
                                     context=object()) == byte_string

    @pytest.mark.parametrize("value", [
        b"bytes",
        u"unicode",
        "native",
        object(),
    ])
    def test_decode_passes_value_through(self, bytes_adapted, value):
        """
        :py:meth:`tls.utils.BytesAdapter._decode` decodes
        :py:class:`bytes` as :py:class:`bytes`.
        """
        assert bytes_adapted._decode(value, context=object()) is value


@pytest.mark.parametrize("bytestring,encoded", [
    (b"", b"\x00" + b""),
    (b"some value", b"\x0A" + b"some value"),
    (b"a" * 255, b"\xff" + b"a" * 255),
])
class TestPrefixedBytesWithDefaultLength(object):
    """
    Tests for :py:func:`tls.utils.PrefixedBytes` with the default
    :py:func:`construct.macros.UBInt8` ``length_field`` construct.
    """

    @pytest.fixture
    def prefixed_bytes(self):
        """
        A trivial :py:func:`tls.utils.PrefixedBytes` construct with
        the default :py:func:`construct.macros.UBInt8` length field.
        """
        return PrefixedBytes("PrefixedBytes")

    def test_build(self, prefixed_bytes, bytestring, encoded):
        """
        :py:meth:`tls.utils.PrefixedBytes` encodes
        :py:class:`bytes` as a length-prefixed byte sequence.
        """
        assert prefixed_bytes.build(bytestring) == encoded

    def test_parse(self, prefixed_bytes, bytestring, encoded):
        """
        :py:meth:`tls.utils.PrefixedBytes` decodes a
        length-prefixed byte sequence as :py:class:`bytes`.
        """
        assert prefixed_bytes.parse(encoded) == bytestring

    def test_round_trip(self, prefixed_bytes, bytestring, encoded):
        """
        :py:meth:`tls.utils.PrefixedBytes` decodes a
        length-prefixed binary sequence encoded by
        :py:meth:`tls.utils.PrefixedBytes` and vice versa.
        """
        parsed = prefixed_bytes.parse(encoded)
        assert prefixed_bytes.build(parsed) == encoded
        unparsed = prefixed_bytes.build(bytestring)
        assert prefixed_bytes.parse(unparsed) == bytestring


@pytest.mark.parametrize("bytestring,encoded,length_field", [
    (b"", b"\x00\x00" + b"", UBInt16("length")),
    (b"some value", b"\x00\x00\x0A" + b"some value", UBInt24("length"))
])
class TestPrefixedBytesWithOverriddenLength(object):
    """
    Tests for :py:func:`tls.utils.PrefixedBytes` with a user-supplied
    ``length_field`` construct.
    """

    def test_build(self, bytestring, encoded, length_field):
        """
        :py:meth:`tls.utils.PrefixedBytes` uses the supplied
        ``length_field`` to encode :class:`bytes` as a length-prefix
        binary sequence.
        """
        prefixed_bytes = PrefixedBytes("name", length_field=length_field)
        assert prefixed_bytes.build(bytestring) == encoded

    def test_parse(self, bytestring, encoded, length_field):
        """
        :py:meth:`tls.utils.PrefixedBytes` decodes a length-prefixed
        binary sequence into :py:class:`bytes` according to the
        supplied ``length_field``.
        """
        prefixed_bytes = PrefixedBytes("name", length_field=length_field)
        assert prefixed_bytes.parse(encoded) == bytestring

    def test_round_trip(self, bytestring, encoded, length_field):
        """
        :py:meth:`tls.utils.PrefixedBytes` decodes a length-prefixed
        binary sequence encoded by :py:meth:`tls.utils.PrefixedBytes`
        when the two share a ``length_field`` and vice versa.
        """
        prefixed_bytes = PrefixedBytes("name", length_field)
        parsed = prefixed_bytes.parse(encoded)
        assert prefixed_bytes.build(parsed) == encoded
        unparsed = prefixed_bytes.build(bytestring)
        assert prefixed_bytes.parse(unparsed) == bytestring


@pytest.mark.parametrize(
    "ints,uint8_encoded",
    [([], b'\x00\x00' + b''),
     ([1, 2, 3], b'\x00\x03' + b'\x01\x02\x03'),
     ([1] * 65535, b'\xFF\xFF' + b'\x01' * 65535)])
class TestTLSPrefixedArray(object):
    """
    Tests for :py:func:`tls.utils.TLSPrefixedArray`.
    """

    @pytest.fixture
    def tls_array(self):
        """
        A :py:func:`tls.utils.TLSPrefixedArray` of
        :py:func:`construct.macros.UBInt8`.
        """
        return TLSPrefixedArray(UBInt8("digit"))

    def test_build(self, tls_array, ints, uint8_encoded):
        """
        A :py:meth:`tls.utils.TLSPrefixedArray` specialized on a given
        :py:func:`construct.Construct` encodes a sequence of objects
        as a 16-bit length followed by each object as encoded by that
        construct.
        """
        assert tls_array.build(ints) == uint8_encoded

    def test_parse(self, tls_array, ints, uint8_encoded):
        """
        A :py:meth:`tls.utils.TLSPrefixedArray` specialized on a given
        :py:func:`construct.Construct` decodes a binary sequence,
        prefixed by its 16-bit length, as a :py:class:`list` of
        objects decoded by that construct.
        """
        assert tls_array.parse(uint8_encoded) == ints

    def test_round_trip(self, tls_array, ints, uint8_encoded):
        """
        A :py:meth:`tls.utils.TLSPrefixedArray` decodes a
        length-prefixed binary sequence encoded by a
        :py:meth:`tls.utils.TLSPrefixedArray` specialized on the same
        construct and vice versa.
        """

        parsed = tls_array.parse(uint8_encoded)
        assert tls_array.build(parsed) == uint8_encoded
        unparsed = tls_array.build(ints)
        assert tls_array.parse(unparsed) == ints


class Equals5(Validator):
    """
    A test fixture :py:class:`construct.adapters.Validator` subclass
    that ensures a numeric field equals 5.
    """

    def _validate(self, obj, context):
        return obj == 5


class TestTLSPrefixedArrayWithLengthValidator(object):
    """
    Tests for :py:class:`tls.utils.TLSPrefixedArray` with a
    ``length_validator``.
    """

    @pytest.fixture
    def TLSUBInt8Array(self):  # noqa
        """
        A :py:class:`tls.utils.TLSPrefixedArray` specialized on
        :py:func:`construct.macros.UBInt8`
        """
        return TLSPrefixedArray(UBInt8("data"))

    @pytest.fixture
    def TLSUBInt8Length5Array(self):  # noqa
        """
        Like
        :py:meth:`TLSPrefixedArrayWithLengthValidator.TLSUBInt8Length5Array`,
        but only accepts arrays of length 5.
        """
        return TLSPrefixedArray(UBInt8("data"),
                                length_validator=Equals5)

    @pytest.mark.parametrize('invalid', [
        [1, 2, 3, 4],  # noqa
        [1, 2, 3, 4, 5, 6],
    ])
    def test_build_invalid(self, TLSUBInt8Length5Array, invalid):
        """
        :py:class:`tls.utils.TLSPrefixedArray` raises a
        :py:exc:`construct.adapters.ValidationError` when encoding a
        list with an invalid length.
        """
        with pytest.raises(ValidationError):
            TLSUBInt8Length5Array.build(invalid)

    @pytest.mark.parametrize('invalid', [
        b'\x00\x04' + b'\x01\x02\x03\x04',  # noqa
        b'\x00\x06' + b'\x01\x02\x03\x04\x05\x06',
    ])
    def test_parse_invalid(self, TLSUBInt8Length5Array, invalid):
        """
        :py:class:`tls.utils.TLSPrefixedArray` raises a
        :py:exc:`construct.adapters.ValidationError` when decoding an
        array with an invalid length.
        """
        with pytest.raises(ValidationError):
            TLSUBInt8Length5Array.parse(invalid)

    def test_parse_valid(self, TLSUBInt8Length5Array, TLSUBInt8Array):  # noqa
        """
        :py:class:`tls.utils.TLSPrefixedArray` decodes an array that
        passes validation.
        """
        valid = b'\x00\x05' + b'\x01\x02\x03\x04\x05'
        assert TLSUBInt8Array.parse(valid) == TLSUBInt8Array.parse(valid)

    def test_build_valid(self, TLSUBInt8Length5Array, TLSUBInt8Array):   # noqa
        """
        :py:class:`tls.utils.TLSPrefixedArray` encodes an array that
        passes validation.
        """
        valid = [1, 2, 3, 4, 5]
        assert TLSUBInt8Array.build(valid) == TLSUBInt8Array.build(valid)


class IntegerEnum(enum.Enum):
    """
    An enum of :py:class:`int` instances.  Used as a test fixture.
    """
    FIRST = 1
    SECOND = 2
    MILLION = 1 << 20


class UnicodeEnum(enum.Enum):
    """
    An enum of :py:class:`str` (or :py:class:`unicode`) instances.  Used as
    a test fixture.
    """
    TEXT = u"\u2022 TEXT"


class TestEnumClass(object):
    """
    Tests for :py:func:`tls.utils.EnumClass`.
    """

    @pytest.fixture
    def UBInt8Enum(self):  # noqa
        """
        A :py:func:`tls.utils.EnumClass` that adapts
        :py:class:`IntegerEnum`'s members to :py:func:`UBInt8`.
        """
        return EnumClass(UBInt8("type"), IntegerEnum)

    def test_build(self, UBInt8Enum):  # noqa
        """
        :py:func:`tls.utils.EnumClass` encodes members of its enum
        according to its construct.
        """
        assert UBInt8Enum.build(IntegerEnum.FIRST) == b'\x01'

    def test_parse(self, UBInt8Enum):  # noqa
        """
        :py:func:`tls.utils.EnumClass` decodes a binary sequence as
        members of its enum via its construct.
        """
        assert UBInt8Enum.parse(b'\x02') == IntegerEnum.SECOND

    def test_build_enum_has_wrong_type(self, UBInt8Enum):  # noqa
        """
        :py:func:`tls.utils.EnumClass` raises
        :py:exc:`construct.adapters.MappingError` when encoding
        something that isn't a member of its enum.
        """
        with pytest.raises(MappingError):
            UBInt8Enum.build(UnicodeEnum.TEXT)


@pytest.mark.parametrize('type_,value,encoded', [
    (IntegerEnum.FIRST, 1, b'\x01' + b'\x00\x01'),
    (IntegerEnum.SECOND, 1, b'\x02' + b'\x00\x00\x01'),
])
class TestEnumSwitch(object):
    """
    Tests for :py:func:`tls.utils.EnumSwitch`.
    """

    @pytest.fixture
    def UBInt8EnumMappedStruct(self):  # noqa
        """
        A :py:class:`construct.core.Struct` containing an
        :py:func:`tls.utils.EnumSwitch` that switches on
        :py:class:`IntegerEnum`.  The struct's ``value`` field varies
        depending on the value of its ``type`` and the corresponding
        enum member specified in the ``value_choices`` dictionary
        passed to the :py:func:`tls.utils.EnumSwitch`.
        """
        return Struct(
            "UBInt8EnumMappedStruct",
            *EnumSwitch(type_field=UBInt8("type"),
                        type_enum=IntegerEnum,
                        value_field="value",
                        value_choices={
                            IntegerEnum.FIRST: UBInt16("UBInt16"),
                            IntegerEnum.SECOND: UBInt24("UBInt24")}))

    def test_build(self, UBInt8EnumMappedStruct, type_, value, encoded):  # noqa
        """
        A struct that contains :py:func:`tls.utils.EnumSwitch` encodes
        its ``value_field`` according to the enum member specified in
        its ``type_field``.
        """
        container = Container(type=type_, value=value)
        assert UBInt8EnumMappedStruct.build(container) == encoded

    def test_parse(self, UBInt8EnumMappedStruct, type_, value, encoded):  # noqa
        """
        A struct that contains :py:func:`tls.utils.EnumSwitch` decodes
        its value field according to the enum member specified by its
        ``type_field``.
        """
        container = UBInt8EnumMappedStruct.parse(encoded)
        assert Container(type=type_, value=value) == container

    def test_round_trip(self, UBInt8EnumMappedStruct, type_, value, encoded):  # noqa
        """
        A struct that contains :py:func:`tls.utils.EnumSwitch` decodes
        a binary sequence encoded by a struct with that same
        :py:func:`tls.utils.EnumSwitch` and vice versa.
        """
        parsed = UBInt8EnumMappedStruct.parse(encoded)
        assert UBInt8EnumMappedStruct.build(parsed) == encoded

        container = Container(type=type_, value=value)
        unparsed = UBInt8EnumMappedStruct.build(container)
        assert UBInt8EnumMappedStruct.parse(unparsed) == container


@pytest.mark.parametrize('min_size,num,acceptable', [
    (0, 0, True),
    (1, 0, False),
    (1, 1, True),
    (1, 2, True),
])
def test_size_at_least_validate(min_size, num, acceptable):
    """
    :py:meth:`SizeAtLeast._validate` enforces its minimum size
    inclusively when encoding numbers.
    """
    bounded = SizeAtLeast(Construct(name="test"), min_size=min_size)
    if acceptable:
        assert bounded._validate(num, context=object())
    else:
        assert not bounded._validate(num, context=object())


@pytest.mark.parametrize('max_size,num,acceptable', [
    (0, 0, True),
    (1, 0, True),
    (1, 1, True),
    (1, 2, False),
])
def test_size_at_most_validate(max_size, num, acceptable):
    """
    :py:meth:`SizeAtMost._validate` enforces its maximum size
    inclusively when encoding numbers.
    """
    bounded = SizeAtMost(Construct(name="test"), max_size=max_size)
    if acceptable:
        assert bounded._validate(num, context=object())
    else:
        assert not bounded._validate(num, context=object())


@pytest.mark.parametrize('min_size,max_size,num,acceptable', [
    (0, 0, 0, True),
    (0, 2, 0, True),
    (1, 2, 1, True),
    (1, 2, 2, True),
    (1, 2, 3, False)
])
def test_size_within_validate(min_size, max_size, num, acceptable):
    """
    :py:meth:`SizeWithin._validate` enforces its maximum size
    inclusively when encoding numbers.
    """
    bounded = SizeWithin(Construct(name="test"),
                         min_size=min_size, max_size=max_size)
    if acceptable:
        assert bounded._validate(num, context=object())
    else:
        assert not bounded._validate(num, context=object())
