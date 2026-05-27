#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import json
import logging
from .agentconffile import (
    conffilename,
    medullaPath,
    directoryconffile,
    pulseTempDir,
    conffilenametmp,
    rotation_file,
)

import lmdb

logger = logging.getLogger()


class manageskioskdb:
    def __init__(self, namebase="kiosk"):
        """Init the manageskioskdb class.

        Args:
            self: The instance of the class.
            namebase (str, optional): The base name for the database. Defaults to "kiosk"."""

        name_launch_cmd_db = f"{namebase}launch_cmd_db"
        self.openbool = False
        path_bd = self.bddir()
        if path_bd is not None:
            # Check if the directory exists, if not, create it.
            if not os.path.exists(path_bd):
                os.makedirs(path_bd, mode=0o700)
            self.name_launch_cmd_db = os.path.join(path_bd, name_launch_cmd_db)
            if sys.platform.startswith("darwin"):
                if not os.path.isdir(self.name_launch_cmd_db):
                    os.makedirs(self.name_launch_cmd_db, mode=0o700)

    def openbase(self):
        """Open the database if it is not already open. Setup the env and dblaunchcmd attributes.
        self.env corresponds to the engine
        self.dblaunchcmd corresponds to the cursor / session of the database.

        Args:
            self: The instance of the class.
            """
        self.env = lmdb.open(self.name_launch_cmd_db, map_size=10485760)
        self.dblaunchcmd = self.env.begin(write=True)

    def closebase(self):
        """Close the database file if it's open.

        Args:
            self: The instance of the class.
        """
        self.env.close()

    def bddir(self):
        """Generate a path for the database directory based on the operating system.
        Args:
            self: The instance of the class.
        Returns:
            str: The path to the database directory, or None if the platform is unsupported.
        """
        if sys.platform.startswith("linux"):
            return os.path.join("/", "var", "lib", "pulse2", "BDKiosk")
        elif sys.platform.startswith("win"):
            return os.path.join(medullaPath(), "var", "tmp", "BDKiosk")
        elif sys.platform.startswith("darwin"):
            return os.path.join("/", "Library", "Application Support", "Pulse", "BDKiosk")
        else:
            return None

    def set_cmd_launch(self, idpackage, str_cmd_launch):
        """Push a key-value pair into the database, where the key is the package ID and the value is the command to launch the application.

        Args:
            self: The instance of the class.
            idpackage (str): The package ID to be used as the key in the database.
            str_cmd_launch (str): The command to launch the application, to be stored as the value in the database.
        Returns:
            bool: True if the operation was successful, False otherwise.
        """

        if idpackage == "":
            return False

        self.openbase()
        if isinstance(idpackage, str):
            idpackage = idpackage.encode("utf-8")
        if isinstance(str_cmd_launch, str):
            str_cmd_launch = str_cmd_launch.encode("utf-8")

        try:
            self.dblaunchcmd.put(idpackage, str_cmd_launch)
        except:
            self.closebase()
            return False

        self.dblaunchcmd.commit()
        return True

    def get_cmd_launch(self, idpackage):
        """Get the value associated with a given key (package ID) from the database, which represents the command to launch the application.

        Args:
            self: The instance of the class.
            idpackage (str): The package ID to be used as the key in the database.

        Returns:
            str: The command to launch the application, or an empty string if the key does not exist.
        """
        if idpackage == "":
            return ""
        data = ""
        self.openbase()
        if isinstance(idpackage, str):
            idpackage = idpackage.encode("utf-8")
        data = self.dblaunchcmd.get(idpackage)
        self.closebase()
        if data is None:
            return ""
        data = data.decode("utf-8")
        return data

    def del_cmd_launch(self, idpackage):
        """Delete the key-value pair associated with a given key (package ID) from the database.

        Args:
            self: The instance of the class.
            idpackage (str): The package ID to be used as the key in the database.
        """
        if idpackage == "":
            return
        self.openbase()
        if isinstance(idpackage, str):
            idpackage = idpackage.encode("utf-8")
        data = self.dblaunchcmd.delete(idpackage)
        self.closebase()

    def get_all_obj_launch(self):
        """Get all key-value pairs from the database, where keys are package IDs and values are commands to launch applications.

        Args:
            self: The instance of the class.

        Returns:
            dict: A dictionary containing all key-value pairs from the database, with keys and values decoded from bytes to strings.
        """
        self.openbase()
        result = {key.decode("utf-8"): value.decode("utf-8") for key, value in self.dblaunchcmd.cursor()}
        self.closebase()
        return result

    def get_all_cmd_launch(self):
        """Get all key-value pairs from the database, excluding the reserved key for JSON name-ID package mapping.

        Args:
            self: The instance of the class.

        Returns:
            dict: A dictionary containing all key-value pairs from the database, excluding the reserved key, with keys and values decoded from bytes to strings.
        """
        self.openbase()

        result = {key.decode("utf-8"): value.decode("utf-8") for key, value in self.dblaunchcmd.cursor() if key != b"str_json_name_id_package"}

        self.closebase()
        return result

    ################################################################################################
    # key "str_json_name_id_package" json string reserved to doing match between name  and idpackage
    def get_obj_ref(self):
        """Get the mapping of application names to package IDs from the database, which is stored as a JSON string under a reserved key.

        Args:
            self: The instance of the class.

        Returns:
            dict: A dictionary mapping application names to package IDs, decoded from the JSON string stored in the database. If the reserved key does not exist, an empty dictionary is returned.
        """
        str_name_idpackage = {}
        strjson = self.get_cmd_launch("str_json_name_id_package")
        return json.loads(str(strjson)) if strjson != "" else {}

    def get_ref_package_for_name(self, name):
        """Get the package ID associated with a given application name from the database, using the mapping stored as a JSON string under a reserved key.

        Args:
            self: The instance of the class.
            name (str): The application name for which to retrieve the associated package ID.

        Returns:
            str: The package ID associated with the given application name, or an empty string if the name does not exist in the mapping.
        """
        str_name_idpackage = ""
        strjson = self.get_cmd_launch("str_json_name_id_package")
        if strjson != "":
            str_name_idpackage = json.loads(str(strjson))
            if name in str_name_idpackage:
                return str_name_idpackage[name]
        else:
            str_name_idpackage = ""
        return ""

    def set_ref_package_for_name(self, name, id_package):
        """Set the mapping of an application name to a package ID in the database, by updating the JSON string stored under a reserved key.

        Args:
            self: The instance of the class.
            name (str): The application name to be mapped.
            id_package (str): The package ID to be associated with the application name.

        Returns:
            None
        """

        str_name_id_package = self.get_obj_ref()
        str_name_id_package[str(name)] = str(id_package)
        self.set_cmd_launch("str_json_name_id_package", json.dumps(str_name_id_package))

    def del_ref_name_for_package(self, name):
        """Delete the mapping of an application name to a package ID from the database, by updating the JSON string stored under a reserved key.

        Args:
            self: The instance of the class.
            name (str): The application name for which to delete the associated package ID.
        """
        str_name_id_package = self.get_obj_ref()
        try:
            del str_name_id_package[str(name)]
            self.set_cmd_launch(
                "str_json_name_id_package", json.dumps(str_name_id_package)
            )
        except KeyError:
            pass
