from setuptools import setup

import os
import sys

if sys.platform.startswith('linux'):
    fileconf = os.path.join("/", "etc" ,"pulse-xmpp-agent")
elif sys.platform.startswith('win'):
    fileconf = os.path.join(os.environ["ProgramFiles"], "Pulse", "etc")
elif sys.platform.startswith('darwin'):
    fileconf = os.path.join("/", "Library", "Application Support", "Pulse", "etc")


setup(
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='pulse xmpp agent',
    name='pulse_xmpp_agent', 
    version='0.1',
    description = 'XMPP Agent for pulse',
    url='https://www.siveo.net/',
    packages=['pulse_xmpp_agent', 'pulse_xmpp_agent.lib', 'pulse_xmpp_agent.pluginsmachine', 'pulse_xmpp_agent.pluginsrelay'],
    test_suite='',
    package_data={},
    entry_points={},
    extras_require={},
    install_requires=[],
    )

