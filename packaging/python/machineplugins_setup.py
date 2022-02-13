#
# (c) 2016-2020 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

from setuptools import setup
from distutils.command.install import INSTALL_SCHEMES

import os

with open("README.md", "r") as fh:
    long_description = fh.read()

for scheme in list(INSTALL_SCHEMES.values()):
    scheme['data'] = os.path.join(scheme['purelib'], "pulse_xmpp_agent")

setup(
    name="pulse_machine_plugins",
    version="2.1.7",
    author="SIVEO",
    author_email="support@siveo.net",
    description="XMPP Machine agent plugins for pulse",
    long_description=long_description,
    url="https://www.siveo.net/",
    include_package_data=True,
    packages=[
        'pulse_xmpp_agent.pluginsmachine',
        'pulse_xmpp_agent.descriptor_scheduler_machine'],
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: OS Independent",
    ],
    install_requires=['pulse_xmpp_agent'],
)
