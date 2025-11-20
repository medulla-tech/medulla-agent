# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import setup
from distutils.command.install import INSTALL_SCHEMES

import os

with open("README.md", "r") as fh:
    long_description = fh.read()

for scheme in list(INSTALL_SCHEMES.values()):
    scheme["data"] = os.path.join(scheme["purelib"], "pulse_xmpp_agent")

setup(
    name="pulse_machine_plugins",
    version="5.4.3",
    author="SIVEO",
    author_email="contact@medulla-tech.io",
    description="XMPP Machine agent plugins for Medulla",
    long_description=long_description,
    url="https://medulla-tech.io/",
    include_package_data=True,
    packages=[
        "pulse_xmpp_agent.pluginsmachine",
        "pulse_xmpp_agent.descriptor_scheduler_machine",
    ],
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: OS Independent",
    ],
    install_requires=["pulse_xmpp_agent"],
)
