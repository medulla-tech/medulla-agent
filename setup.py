#
# (c) 2016-2017 siveo, http://www.siveo.net
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
from distutils.command.install import INSTALL_SCHEMES
from distutils.sysconfig import get_python_lib
import sys
import os


path = get_python_lib() ;

if sys.platform.startswith('linux'):
    fileconf = os.path.join("/", "etc" ,"pulse-xmpp-agent")
elif sys.platform.startswith('win'):
    fileconf = os.path.join(os.environ["ProgramFiles"], "Pulse", "etc")
elif sys.platform.startswith('darwin'):
    fileconf = os.path.join("/", "Library", "Application Support", "Pulse", "etc")

for scheme in INSTALL_SCHEMES.values():
    scheme['data'] = os.path.join(scheme['purelib'], "pulse_xmpp_agent")

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
    version='2.0.6',
    debian_distro='stretch',
    description = 'XMPP Agent for pulse',
    url='https://www.siveo.net/',
    packages=['pulse_xmpp_agent', 'pulse_xmpp_agent.lib', 'pulse_xmpp_agent.pluginsmachine', 'pulse_xmpp_agent.script', 'pulse_xmpp_agent.descriptor_scheduler_machine'],
    data_files=[('script', ['pulse_xmpp_agent/script/getlastuser.ps1', 'pulse_xmpp_agent/script/create-profile.ps1']),
                  ('', ['pulse_xmpp_agent/agentversion']), (path + '/pulse_xmpp_agent/pluginsmachine', ['pulse_xmpp_agent/plugins_common/plugin_enddeploy.py', 'pulse_xmpp_agent/plugins_common/plugin_force_setup_agent.py', 'pulse_xmpp_agent/plugins_common/plugin_applicationdeploymentjson.py', 'pulse_xmpp_agent/plugins_common/plugin_start.py', 'pulse_xmpp_agent/plugins_common/plugin_installplugin.py', 'pulse_xmpp_agent/plugins_common/plugin_requestinfo.py', 'pulse_xmpp_agent/plugins_common/plugin_restartbot.py', 'pulse_xmpp_agent/plugins_common/plugin_shellcommand.py', 'pulse_xmpp_agent/plugins_common/plugin_asynchromeremoteshell.py',  'pulse_xmpp_agent/plugins_common/plugin_guacamole.py', 'pulse_xmpp_agent/plugins_common/plugin_installkey.py', 'pulse_xmpp_agent/plugins_common/plugin_installpluginscheduled.py', 'pulse_xmpp_agent/plugins_common/plugin_resultapplicationdeploymentjson.py', 'pulse_xmpp_agent/plugins_common/plugin_reverse_ssh_on.py', 'pulse_xmpp_agent/plugins_common/plugin_asynchroremoteQA.py','pulse_xmpp_agent/plugins_common/plugin_updateagent.py','pulse_xmpp_agent/plugins_common/plugin_deploysyncthing.py']),],
    test_suite='',
    package_data={},
    entry_points={},
    extras_require={},
    install_requires=[
        'netifaces >= 0.10.5',
        'configparser >= 3.5.0',
        'utils >= 0.9.0',
        'sleekxmpp >= 1.3.1',
        'zipfile2 >= 0.0.12',
        'pycurl >= 7.43.0',
        'lxml >= 3.6.0',
        'pycrypto >= 2.6.1',
        'croniter >= 0.3.16',
        'psutil >= 5.4.3',
        'pysftp >= 0.2.9',
        'syncthing >= 2.3.1',
        'requests >= 2.8.14',
        'pathlib >= 1.0.1 ; platform_system=="Windows"',
        'pywin32 >= 219 ; platform_system=="Windows"',
        'comtypes >= 1.1.3 ; platform_system=="Windows"',
        'wmi >= 1.4.9 ; platform_system=="Windows"'
    ],
    )
