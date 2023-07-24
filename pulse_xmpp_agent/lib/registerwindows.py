# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import platform
import logging

if sys.platform.startswith("win"):
    import winreg


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
        self.keysregister = {
            "HKEY_CLASSES_ROOT": "Registry entries subordinate to this key define types (or classes) of documents and the properties associated with those types.Shell and COM applications use the information stored under this key.",
            "HKEY_CURRENT_USER": "Registry entries subordinate to this key define the preferences of the current user. These preferences include the settings of environment variables, data about program groups, colors, printers, network connections, and application preferences.",
            "HKEY_LOCAL_MACHINE": "Registry entries subordinate to this key define the physical state of the computer, including data about the bus type, system memory, and installed hardware and software.",
            "HKEY_USERS": "Registry entries subordinate to this key define the default user configuration for new users on the local computer and the user configuration for the current user.",
            "HKEY_PERFORMANCE_DATA": "Registry entries subordinate to this key allow you to access performance data. The data is not actually stored in the registry; the registry functions cause the system to collect the data from its source.",
            "HKEY_CURRENT_CONFIG": "Contains information about the current hardware profile of the local computer system.",
            "HKEY_DYN_DATA": "This key is not used in versions of Windows after 98.",
            "KEY_ALL_ACCESS": "Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.",
            "KEY_WRITE": "Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.",
            "KEY_READ": "Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.",
            "KEY_EXECUTE": "Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.",
            "KEY_QUERY_VALUE": "Required to query the values of a registry key.",
            "KEY_SET_VALUE": "Required to create, delete, or set a registry value.",
            "KEY_CREATE_SUB_KEY": "Required to create a subkey of a registry key.",
            "KEY_ENUMERATE_SUB_KEYS": "Required to enumerate the subkeys of a registry key.",
            "KEY_NOTIFY": "Required to request change notifications for a registry key or for subkeys of a registry key.",
            "KEY_CREATE_LINK": "Reserved for system use.",
            "KEY_WOW64_64KEY": "Indicates that an application on 64-bit Windows should operate on the 64-bit registry view.",
            "KEY_WOW64_32KEY": "Indicates that an application on 64-bit Windows should operate on the 32-bit registry view.",
        }

        self.typeregister = {
            "REG_BINARY": "Binary data in any form.",
            "REG_DWORD": "32-bit number.",
            "REG_DWORD_LITTLE_ENDIAN": "A 32-bit number in little-endian format.",
            "REG_DWORD_BIG_ENDIAN": "A 32-bit number in big-endian format.",
            "REG_EXPAND_SZ": "Null-terminated string containing references to environment variables (%PATH%).",
            "REG_LINK": "A Unicode symbolic link.",
            "REG_MULTI_SZ": "A sequence of null-terminated strings, terminated by two null characters. (Python handles this termination automatically.)",
            "REG_NONE": "No defined value type.",
            "REG_RESOURCE_LIST": "A device-driver resource list.",
            "REG_FULL_RESOURCE_DESCRIPTOR": "A hardware setting.",
            "REG_RESOURCE_REQUIREMENTS_LIST": "A hardware resource list.",
            "REG_SZ": "A null-terminated string.",
        }
        self.bitness = platform.architecture()[0]
        if self.bitness == "32bit":
            self.other_view_flag = winreg.KEY_WOW64_64KEY
        elif self.bitness == "64bit":
            self.other_view_flag = winreg.KEY_WOW64_32KEY

    def regkey_exists(self, key):
        """
        this function check if the registry key exist
        Args:
        key:  the registry key to check

        Returns:
        True if the key exist, False otherwise
        """
        return key in self.keysregister

    def is_exist_type(self, registrytype):
        return type in self.typeregister

    def descriptionkey(self, key):
        return self.keysregister[key] if self.regkey_exists(key) else ""

    def descriptiontype(self, registertype):
        if self.is_exist_type(registertype):
            return self.keysregister[registertype]
        return ""

    def getType(self, registrytype):
        if registrytype in self.typeregister:
            if registrytype == "REG_BINARY":
                return winreg.REG_BINARY
            elif registrytype == "REG_DWORD":
                return winreg.REG_DWORD
            elif registrytype == "REG_DWORD_LITTLE_ENDIAN":
                return winreg.REG_DWORD_LITTLE_ENDIAN
            elif registrytype == "REG_DWORD_BIG_ENDIAN":
                return winreg.REG_DWORD_BIG_ENDIAN
            elif registrytype == "REG_EXPAND_SZ":
                return winreg.REG_EXPAND_SZ
            elif registrytype == "REG_LINK":
                return winreg.REG_LINK
            elif registrytype == "REG_MULTI_SZ":
                return winreg.REG_MULTI_SZ
            elif registrytype == "REG_NONE":
                return winreg.REG_NONE
            elif registrytype == "REG_RESOURCE_LIST":
                return winreg.REG_RESOURCE_LIST
            elif registrytype == "REG_FULL_RESOURCE_DESCRIPTOR":
                return winreg.REG_FULL_RESOURCE_DESCRIPTOR
            elif registrytype == "REG_RESOURCE_REQUIREMENTS_LIST":
                return winreg.REG_RESOURCE_REQUIREMENTS_LIST
            elif registrytype == "REG_SZ":
                return winreg.REG_SZ
        raise

    def getkey(self, key):
        if key in self.keysregister:
            if key == "HKEY_CLASSES_ROOT":
                return winreg.HKEY_CLASSES_ROOT
            elif key == "HKEY_CURRENT_USER":
                return winreg.HKEY_CURRENT_USER
            elif key == "HKEY_LOCAL_MACHINE":
                return winreg.HKEY_LOCAL_MACHINE
            elif key == "HKEY_USERS":
                return winreg.HKEY_USERS
            elif key == "HKEY_PERFORMANCE_DATA":
                return winreg.HKEY_PERFORMANCE_DATA
            elif key == "HKEY_CURRENT_CONFIG":
                return winreg.HKEY_CURRENT_CONFIG
            elif key == "HKEY_DYN_DATA":
                return winreg.HKEY_DYN_DATA
            elif key == "KEY_ALL_ACCESS":
                return winreg.KEY_ALL_ACCESS
            elif key == "KEY_WRITE":
                return winreg.KEY_WRITE
            elif key == "KEY_READ":
                return winreg.KEY_READ
            elif key == "KEY_EXECUTE":
                return winreg.KEY_EXECUTE
            elif key == "KEY_QUERY_VALUE":
                return winreg.KEY_QUERY_VALUE
            elif key == "KEY_SET_VALUE":
                return winreg.KEY_SET_VALUE
            elif key == "KEY_CREATE_SUB_KEY":
                return winreg.KEY_CREATE_SUB_KEY
            elif key == "KEY_ENUMERATE_SUB_KEYS":
                return winreg.KEY_ENUMERATE_SUB_KEYS
            elif key == "KEY_NOTIFY":
                return winreg.KEY_NOTIFY
            elif key == "KEY_CREATE_LINK":
                return winreg.KEY_CREATE_LINK
            elif key == "KEY_WOW64_64KEY":
                return winreg.KEY_WOW64_64KEY
            elif key == "KEY_WOW64_32KEY":
                return winreg.KEY_WOW64_32KEY
        raise

    def getother_view_flag(self):
        return self.other_view_flag


class RegisterWindows:
    def __init__(self):
        pass

    def readkey(self):
        reg_constants = constantregisterwindows()
        try:
            hive = self.split("\\")[0].strip('"')
            sub_key = self.split("\\")[-1].strip('"')
            path = self.replace(hive + "\\", "").replace("\\" + sub_key, "").strip('"')
            key = winreg.OpenKey(
                reg_constants.getkey(hive),
                path,
                0,
                winreg.KEY_READ | reg_constants.getother_view_flag(),
            )
            key_value = winreg.QueryValueEx(key, sub_key)
            return str(key_value[0])
        except Exception as e:
            logging.getLogger().error(str(e))
            return ""

    def readkeyKeyPathVariable(self, strpath, strnamevariable):
        reg_constants = constantregisterwindows()
        try:
            key = winreg.OpenKey(
                reg_constants.getkey(self),
                strpath,
                0,
                winreg.KEY_READ | reg_constants.getother_view_flag(),
            )
            key_value = winreg.QueryValueEx(key, strnamevariable)
            return str(key_value[0])
        except Exception as e:
            logging.getLogger().error(str(e))
            return ""
