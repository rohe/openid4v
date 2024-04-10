#!/usr/bin/env python
#
# Copyright (C) 2017 Roland Hedberg, Sweden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import sys

from setuptools import find_packages
from setuptools import setup
from setuptools.command.test import test as TestCommand

__author__ = 'Roland Hedberg'


extra_install_requires = []

with open('src/openid4v/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

setup(
    name="openid4v",
    version=version,
    description="Python implementation of OpenID Verifiable Credentials Issuer, Wallet and Wallet Provider",
    long_description=README,
    long_description_content_type='text/markdown',
    author="Roland Hedberg",
    author_email="roland@catalogix.se",
    license="Apache 2.0",
    url='https://github.com/rohe/openid4v/',
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires=[
        "idpyoidc>=4.0.0"
    ],
    zip_safe=False,
)
