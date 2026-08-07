# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import setup
from distutils.command.install import INSTALL_SCHEMES

import os

with open("README.md", "r") as fh:
    long_description = fh.read()

for scheme in list(INSTALL_SCHEMES.values()):
    scheme["data"] = os.path.join(scheme["purelib"], "pulse_xmpp_master_substitute")

setup(
    name="pulse_xmpp_master_substitute",
    version="5.6.3",
    author="SIVEO",
    author_email="contact@medulla-tech.io",
    description="XMPP substitute for Medulla",
    long_description=long_description,
    url="https://medulla-tech.io/",
    include_package_data=True,
    packages=[
        "pulse_xmpp_master_substitute",
        "pulse_xmpp_master_substitute.bin",
        "pulse_xmpp_master_substitute.descriptor_scheduler_substitute",
        "pulse_xmpp_master_substitute.lib",
        "pulse_xmpp_master_substitute.lib.plugins",
        "pulse_xmpp_master_substitute.lib.plugins.admin",
        "pulse_xmpp_master_substitute.lib.plugins.glpi",
        "pulse_xmpp_master_substitute.lib.plugins.kiosk",
        "pulse_xmpp_master_substitute.lib.plugins.msc",
        "pulse_xmpp_master_substitute.lib.plugins.msc.orm",
        "pulse_xmpp_master_substitute.lib.plugins.pkgs",
        "pulse_xmpp_master_substitute.lib.plugins.pkgs.orm",
        "pulse_xmpp_master_substitute.lib.plugins.utils",
        "pulse_xmpp_master_substitute.lib.plugins.xmpp",
        "pulse_xmpp_master_substitute.pluginsmastersubstitute",
        "pulse_xmpp_master_substitute.script",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "pulse_xmpp_agent",
        "geoip",
        "sqlalchemy >= 0.4",
    ],
)
