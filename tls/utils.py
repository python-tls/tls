# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import operator

import construct

import six


class _UBInt24(construct.Adapter):
    def _encode(self, obj, context):
        return (
            six.int2byte((obj & 0xFF0000) >> 16) +
            six.int2byte((obj & 0x00FF00) >> 8) +
            six.int2byte(obj & 0x0000FF)
        )

    def _decode(self, obj, context):
        obj = bytearray(obj)
        return (obj[0] << 16 | obj[1] << 8 | obj[2])


def UBInt24(name):  # noqa
    """
    A 24-bit integer.

    :param name: The attribute name under which this value will be
        accessible.
    :type name: :py:class:`str`
    """
    return _UBInt24(construct.Bytes(name, 3))


class BytesAdapter(construct.Adapter):
    def _encode(self, obj, context):
        if not isinstance(obj, bytes):
            raise construct.AdaptationError("{} requires bytes, got {}".format(
                self.subcon.name, repr(obj)))
        return obj

    def _decode(self, obj, context):
        return obj


def PrefixedBytes(name, length_field=construct.UBInt8("length")):  # noqa
    """
    Length-prefixed binary data.  This is like a
    :py:func:`construct.macros.PascalString` that raises a
    :py:class:`constrcut.AdaptationError` when encoding something
    other than :py:class:`bytes`.

    :param name: The attribute name under which this value will be
        accessible.
    :type name: :py:class:`str`

    :param length_field: (optional) The prefixed length field.
        Defaults to :py:func:`construct.macros.UBInt8`.
    :type length_field: a :py:class:`construct.core.FormatField`
    """
    return construct.LengthValueAdapter(
        construct.Sequence(
            name,
            length_field,
            BytesAdapter(
                construct.Field("data",
                                operator.attrgetter(length_field.name))))
    )


def TLSPrefixedArray(subconn, length_name="length"):  # noqa
    """
    The `TLS vector type`_.  It specializes on another
    :py:class:`construct.Construct` and then encodes or decodes an
    arbitrarily long list or array of those constructs, prepending or
    reading a leading 16 bit length.

    :param subconn: The construct this array contains.
    :type subconn: `construct.Construct`

    :param length_field: (optional) The attribute name under which the
        :class:`construct.macros.UBInt16` representing this array's
        length will be accessible.  You do not need to provide this
        when encoding a python sequence!
    :type length_field: :py:class:`str`

    ..  _TLS vector type: https://tools.ietf.org/html/rfc5246#section-4.3
    """
    return construct.PrefixedArray(
        subconn,
        length_field=construct.UBInt16(length_name))


def EnumClass(type_field, type_enum):  # noqa
    """
    Maps the members of an :py:class:`enum.Enum` to a single kind of
    :py:class:`construct.Construct`.

    :param type_field: The construct that represents the enum's
        members.  The type of this should correspond to the enum
        members' types; for instance, an enum with a maximum value of
        65535 would use a :py:class:`construct.macros.UBInt16`.
    :type type_field: :py:class:`construct.Construct`

    :param type_enum: The enum to encode and decode.
    :type type_enum: :py:class:`enum.Enum`
    """
    mapping = {member: member.value for member in type_enum}
    return construct.SymmetricMapping(type_field, mapping)


def EnumSwitch(type_field, type_enum, value_field, value_choices):  # noqa
    """
    Maps the members of an :py:class:`enum.Enum` to arbitrary
    :py:func:`construct.Constructs`.  It returns a tuple intended to
    be spliced into another :py:func:`construct.Construct`'s
    definition:

    >>> import construct, enum
    >>> class IntEnum(enum.Enum):
    ...     VALUE = 1
    ...
    >>> construct.Struct(
    ...     "name",
    ...     construct.UBInt8("an_integer"),
    ...     *EnumSwitch(type_field=construct.UBInt8("type"),
    ...                 type_enum=IntEnum,
    ...                 value_field="value",
    ...                 value_choices={
    ...                     IntEnum.VALUE: construct.UBInt8("first"),
    ...      })
    ... )
    ...
    Struct('name')

    :param type_field: The construct that represents the enum's
        members.  The type of this should correspond to the enum
        members' types, so an enum with a maximum value of 65535, for
        example, would use a :py:class:`construct.macros.UBInt16`.
    :type type_field: :py:class:`construct.Construct`

    :param type_enum: The enum to encode and decode.
    :type type_enum: :py:class:`enum.Enum`

    :param value_field: The attribute name under which this value will
        be accessible.
    :type value_field: :py:class:`str`

    :param value_choices: A dictionary that maps members of
        `type_enum` to subconstructs.  This follows
        :py:func:`construct.core.Switch`'s API, so ``_default_`` will
        match any members without an explicit mapping.
    :type value_choices: :py:class:`dict`

    :return: A :py:class:`tuple` of the form (:py:func:`EnumClass`,
             :py:func:`construct.core.Switch`)
    """
    return (EnumClass(type_field, type_enum),
            construct.Switch(value_field,
                             operator.attrgetter(type_field.name),
                             value_choices))
