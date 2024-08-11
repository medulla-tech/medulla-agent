# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

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
    version="3.1.1",
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
        "wheel",
        "slixmpp >= 1.8.2",
        "pycurl >= 7.45.1",
        "lxml >= 4.9.1",
        "croniter >= 1.3.5",
        "psutil >= 5.9.1",
        "cherrypy >= 18.8.0",
        "requests >= 2.28.1",
        "lmdb",
        "PyYAML",
        "netaddr",
        "packaging",
        "pillow",
    ]
    + (
        [
            "pathlib >= 1.0.1",
            "pypiwin32 >= 223",
            "comtypes >= 1.1.14",
            "wmi >= 1.5.1",
            "netifaces2",
            "pycryptodome >= 3.15.0",
        ]
        if "win" in sys.platform
        else [
            "posix_ipc >= 1.0.5",
            "lmdb",
            "netifaces",
            "pycryptodomex >= 3.15.0",
            "xmltodict",
        ]
    ),
)
