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

setup(
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: GPL License",
        "Programming Language :: Python :: 3",
    ],
    keywords="pulse-xmpp-agent",
    name="pulse_xmpp_agent",
    version='3.0.0', # fmt: skip
    debian_distro='stretch',  # fmt: skip
    description="pulse-xmpp-agent",
    url="https://www.siveo.net/",
    packages=["pulse_xmpp_agent"],
    test_suite="",
    package_data={},
    entry_points={},
    extras_require={},
    install_requires=[],
)  # fmt: skip
