# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import setup
from distutils.command.install import INSTALL_SCHEMES

import os

with open("README.md", "r") as fh:
    long_description = fh.read()

for scheme in list(INSTALL_SCHEMES.values()):
    scheme["data"] = os.path.join(scheme["purelib"], "medulla_agent")

setup(
    name="medulla_machine_plugins",
    version="3.1.0",
    author="SIVEO",
    author_email="support@siveo.net",
    description="XMPP Machine agent plugins for medulla",
    long_description=long_description,
    url="https://www.siveo.net/",
    include_package_data=True,
    packages=[
        "medulla_agent.pluginsmachine",
        "medulla_agent.descriptor_scheduler_machine",
    ],
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: OS Independent",
    ],
    install_requires=["medulla_agent"],
)
