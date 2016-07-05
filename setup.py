#!/usr/bin/env python

# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import setuptools

setuptools.setup(
    name="tls",
    version="0.0",
    description="tls",
    long_description="tls",
    install_requires=[
        "attrs",
        "construct",
        "enum34",
    ],
    packages=setuptools.find_packages()
)
