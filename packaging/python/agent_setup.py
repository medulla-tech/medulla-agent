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
    version="5.6.3",
    author="SIVEO",
    author_email="contact@medulla-tech.io",
    description="XMPP Agent for Medulla",
    long_description=long_description,
    url="https://medulla-tech.io/",
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
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: OS Independent",
    ],
    # Common packages
    install_requires=[
        "aiofiles",
        "cherrypy >= 18.8.0",
        "croniter >= 1.3.5",
        "lmdb",
        "lxml >= 4.9.1",
        "netaddr",
        "netifaces_plus",
        "packaging",
        "posix_ipc >= 1.0.5",
        "psutil >= 5.9.1",
        "pillow",
        "pycurl >= 7.45.1",
        "PyYAML",
        "pycryptodome >= 3.15.0",
        "requests >= 2.28.1",
        "slixmpp == 1.8.5",
        "websockets",
        "wheel",
        "xmltodict",
    ] +
    # Windows only packages
    (
        [
            "comtypes >= 1.1.14",
            "pathlib >= 1.0.1",
            "pypiwin32 >= 223",
            "wmi >= 1.5.1",
        ]
        if "win" in sys.platform
    # Linux and Mac only packages
        else [
            "distro",
        ]
    ),
)
