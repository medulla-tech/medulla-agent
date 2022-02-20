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
import sys
from distutils.command.install import INSTALL_SCHEMES

import os

with open("README.md", "r") as fh:
    long_description = fh.read()

for scheme in list(INSTALL_SCHEMES.values()):
    scheme["data"] = os.path.join(scheme["purelib"], "pulse_xmpp_agent")

setup(
    name="pulse_xmpp_agent",
    version="2.1.7",
    author="SIVEO",
    author_email="support@siveo.net",
    description="XMPP Agent for pulse",
    long_description=long_description,
    url="https://www.siveo.net/",
    include_package_data=True,
    packages=[
        "pulse_xmpp_agent",
        "pulse_xmpp_agent.lib",
        "pulse_xmpp_agent.pluginsmachine",
        "pulse_xmpp_agent.script",
        "pulse_xmpp_agent.descriptor_scheduler_machine",
        "pulse_xmpp_agent.lib.ressources.filebrowser.js",
    ],
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "netifaces >= 0.10.5",
        "configparser >= 3.5.0",
        "utils >= 0.9.0",
        "sleekxmpp >= 1.3.1",
        "zipfile2 >= 0.0.12",
        "pycurl >= 7.43.0",
        "lxml >= 3.6.0",
        "pycrypto >= 2.6.1",
        "croniter >= 0.3.16",
        "psutil >= 5.4.3",
        "pysftp >= 0.2.9",
        "cherrypy >= 3.0.0",
        "requests >= 2.8.14",
    ]
    + (
        ["pathlib >= 1.0.1", "pypiwin32 >= 219", "comtypes >= 1.1.3", "wmi >= 1.4.9"]
        if "win" in sys.platform
        else []
    ),
)
