from setuptools import setup, find_packages

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
    packages=['pulse_xmpp_agent', 'pulse_xmpp_agent.lib', 'pulse_xmpp_agent.plugins'],
    test_suite='',
    package_data={},
    entry_points={},
    data_files=[('/etc/pulse-xmpp-agent', ['pulse_xmpp_agent/config/agentconf.ini']),('/etc/pulse-xmpp-agent', ['pulse_xmpp_agent/config/agent.ini']),],
    extras_require={},
    install_requires=[],
    )

