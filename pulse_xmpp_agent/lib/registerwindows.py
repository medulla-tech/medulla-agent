# -*- coding: utf-8; -*-
#
# (c) 2016 siveo, http://www.siveo.net
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

import sys

if sys.platform.startswith('win'):
    import _winreg


def singletonclass(class_):
    instances = {}

    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance


@singletonclass
class constantregisterwindows:

    def __init__(self):
        self.keysregister = {'HKEY_CLASSES_ROOT': 'Registry entries subordinate to this key define types (or classes) of documents and the properties associated with those types.Shell and COM applications use the information stored under this key.',
                             'HKEY_CURRENT_USER': 'Registry entries subordinate to this key define the preferences of the current user. These preferences include the settings of environment variables, data about program groups, colors, printers, network connections, and application preferences.',
                             'HKEY_LOCAL_MACHINE': 'Registry entries subordinate to this key define the physical state of the computer, including data about the bus type, system memory, and installed hardware and software.',
                             'HKEY_USERS': 'Registry entries subordinate to this key define the default user configuration for new users on the local computer and the user configuration for the current user.',
                             'HKEY_PERFORMANCE_DATA': 'Registry entries subordinate to this key allow you to access performance data. The data is not actually stored in the registry; the registry functions cause the system to collect the data from its source.',
                             'HKEY_CURRENT_CONFIG': 'Contains information about the current hardware profile of the local computer system.',
                             'HKEY_DYN_DATA': 'This key is not used in versions of Windows after 98.',
                             'KEY_ALL_ACCESS': 'Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.',
                             'KEY_WRITE': 'Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.',
                             'KEY_READ': 'Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.',
                             'KEY_EXECUTE': 'Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.',
                             'KEY_QUERY_VALUE': 'Required to query the values of a registry key.',
                             'KEY_SET_VALUE': 'Required to create, delete, or set a registry value.',
                             'KEY_CREATE_SUB_KEY': 'Required to create a subkey of a registry key.',
                             'KEY_ENUMERATE_SUB_KEYS': 'Required to enumerate the subkeys of a registry key.',
                             'KEY_NOTIFY': 'Required to request change notifications for a registry key or for subkeys of a registry key.',
                             'KEY_CREATE_LINK': 'Reserved for system use.',
                             'KEY_WOW64_64KEY': 'Indicates that an application on 64-bit Windows should operate on the 64-bit registry view.',
                             'KEY_WOW64_32KEY': 'Indicates that an application on 64-bit Windows should operate on the 32-bit registry view.'
                             }

        self.typeregister = {'REG_BINARY': 'Binary data in any form.',
                             'REG_DWORD': '32-bit number.',
                             'REG_DWORD_LITTLE_ENDIAN': 'A 32-bit number in little-endian format.',
                             'REG_DWORD_BIG_ENDIAN': 'A 32-bit number in big-endian format.',
                             'REG_EXPAND_SZ': 'Null-terminated string containing references to environment variables (%PATH%).',
                             'REG_LINK': 'A Unicode symbolic link.',
                             'REG_MULTI_SZ': 'A sequence of null-terminated strings, terminated by two null characters. (Python handles this termination automatically.)',
                             'REG_NONE': 'No defined value type.',
                             'REG_RESOURCE_LIST': 'A device-driver resource list.',
                             'REG_FULL_RESOURCE_DESCRIPTOR': 'A hardware setting.',
                             'REG_RESOURCE_REQUIREMENTS_LIST': 'A hardware resource list.',
                             'REG_SZ': 'A null-terminated string.'
                             }

    def is_exist_key(self, key):
        """
        this function check if the registry key exist
        Args:
        key:  the registry key to check

        Returns:
        True if the key exist, False otherwise
        """
        if key in self.keysregister:
            return True
        return False

    def is_exist_type(self, registrytype):
        if type in self.typeregister:
            return True
        return False

    def descriptionkey(self, key):
        if self.is_exist_key(key):
            return self.keysregister[key]
        return ""

    def descriptiontype(self, registertype):
        if self.is_exist_type(registertype):
            return self.keysregister[registertype]
        return ""

    def getType(self, registrytype):
        if registrytype in self.typeregister:
            if registrytype == 'REG_BINARY':
                return _winreg.REG_BINARY
            elif registrytype == 'REG_DWORD':
                return _winreg.REG_DWORD
            elif registrytype == 'REG_DWORD_LITTLE_ENDIAN':
                return _winreg.REG_DWORD_LITTLE_ENDIAN
            elif registrytype == 'REG_DWORD_BIG_ENDIAN':
                return _winreg.REG_DWORD_BIG_ENDIAN
            elif registrytype == 'REG_EXPAND_SZ':
                return _winreg.REG_EXPAND_SZ
            elif registrytype == 'REG_LINK':
                return _winreg.REG_LINK
            elif registrytype == 'REG_MULTI_SZ':
                return _winreg.REG_MULTI_SZ
            elif registrytype == 'REG_NONE':
                return _winreg.REG_NONE
            elif registrytype == 'REG_RESOURCE_LIST':
                return _winreg.REG_RESOURCE_LIST
            elif registrytype == 'REG_FULL_RESOURCE_DESCRIPTOR':
                return _winreg.REG_FULL_RESOURCE_DESCRIPTOR
            elif registrytype == 'REG_RESOURCE_REQUIREMENTS_LIST':
                return _winreg.REG_RESOURCE_REQUIREMENTS_LIST
            elif registrytype == 'REG_SZ':
                return _winreg.REG_SZ
        raise

    def getkey(self, key):
        if key in self.keysregister:
            if key == 'HKEY_CLASSES_ROOT':
                return _winreg.HKEY_CLASSES_ROOT
            elif key == 'HKEY_CURRENT_USER':
                return _winreg.HKEY_CURRENT_USER
            elif key == 'HKEY_LOCAL_MACHINE':
                return _winreg.HKEY_LOCAL_MACHINE
            elif key == 'HKEY_USERS':
                return _winreg.HKEY_USERS
            elif key == 'HKEY_PERFORMANCE_DATA':
                return _winreg.HKEY_PERFORMANCE_DATA
            elif key == 'HKEY_CURRENT_CONFIG':
                return _winreg.HKEY_CURRENT_CONFIG
            elif key == 'HKEY_DYN_DATA':
                return _winreg.HKEY_DYN_DATA
            elif key == 'KEY_ALL_ACCESS':
                return _winreg.KEY_ALL_ACCESS
            elif key == 'KEY_WRITE':
                return _winreg.KEY_WRITE
            elif key == 'KEY_READ':
                return _winreg.KEY_READ
            elif key == 'KEY_EXECUTE':
                return _winreg.KEY_EXECUTE
            elif key == 'KEY_QUERY_VALUE':
                return _winreg.KEY_QUERY_VALUE
            elif key == 'KEY_SET_VALUE':
                return _winreg.KEY_SET_VALUE
            elif key == 'KEY_CREATE_SUB_KEY':
                return _winreg.KEY_CREATE_SUB_KEY
            elif key == 'KEY_ENUMERATE_SUB_KEYS':
                return _winreg.KEY_ENUMERATE_SUB_KEYS
            elif key == 'KEY_NOTIFY':
                return _winreg.KEY_NOTIFY
            elif key == 'KEY_CREATE_LINK':
                return _winreg.KEY_CREATE_LINK
            elif key == 'KEY_WOW64_64KEY':
                return _winreg.KEY_WOW64_64KEY
            elif key == 'KEY_WOW64_32KEY':
                return _winreg.KEY_WOW64_32KEY
        raise
