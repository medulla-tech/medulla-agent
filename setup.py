# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

from setuptools import setup

setup(
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: GPL License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='pulse-xmpp-agent',
    name='pulse_xmpp_agent',
    version='2.2.0',
    debian_distro='stretch',
    description='pulse-xmpp-agent',
    url='https://www.siveo.net/',
    packages=['pulse_xmpp_agent'],
    test_suite='',
    package_data={},
    entry_points={},
    extras_require={},
    install_requires=[],
    )
