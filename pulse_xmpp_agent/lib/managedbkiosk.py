#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import json
import logging

import lmdb

logger = logging.getLogger()


class manageskioskdb:
    def __init__(self, namebase="kiosk"):
        name_launch_cmd_db = f"{namebase}launch_cmd_db"
        self.openbool = False
        path_bd = self.bddir()
        if path_bd is not None:
            if not os.path.exists(path_bd):
                os.makedirs(path_bd, mode=0o700)
            self.name_launch_cmd_db = os.path.join(path_bd, name_launch_cmd_db)
            if sys.platform.startswith("darwin"):
                if not os.path.isdir(self.name_launch_cmd_db):
                    os.makedirs(self.name_launch_cmd_db, mode=0o700)

    def openbase(self):
        env = lmdb.open(self.name_launch_cmd_db, map_size=10485760)
        self.dblaunchcmd = env.begin(write=True)

    def closebase(self):
        env.close()

    def bddir(self):
        if sys.platform.startswith("linux"):
            return os.path.join("/", "var", "lib", "pulse2", "BDKiosk")
        elif sys.platform.startswith("win"):
            return os.path.join(
                os.environ["ProgramFiles"], "Pulse", "var", "tmp", "BDKiosk"
            )
        elif sys.platform.startswith("darwin"):
            return os.path.join(
                "/", "Library", "Application Support", "Pulse", "BDKiosk"
            )
        else:
            return None

    def set_cmd_launch(self, idpackage, str_cmd_launch):
        idpackage = str(idpackage)
        self.openbase()
        self.dblaunchcmd.put(bytearray(idpackage), bytearray(str_cmd_launch))
        self.commit()

    def get_cmd_launch(self, idpackage):
        idpackage = str(idpackage)
        data = ""
        self.openbase()
        data = self.dblaunchcmd.get(bytearray(idpackage))
        if data is None:
            data = ""
        self.closebase()
        return str(data)

    def del_cmd_launch(self, idpackage):
        idpackage = str(idpackage)
        self.openbase()
        data = self.dblaunchcmd.delete(bytearray(idpackage))
        self.closebase()

    def get_all_obj_launch(self):
        self.openbase()
        result = {str(k): str(v) for k, v in self.dblaunchcmd}
        self.closebase()
        return result

    def get_all_cmd_launch(self):
        self.openbase()
        result = {
            str(k): str(v)
            for k, v in self.dblaunchcmd
            if str(k) != "str_json_name_id_package"
        }
        self.closebase()
        return result

    ################################################################################################
    # key "str_json_name_id_package" json string reserved to doing match between name  and idpackage
    def get_obj_ref(self):
        str_name_idpackage = {}
        strjson = self.get_cmd_launch("str_json_name_id_package")
        return json.loads(str(strjson)) if strjson != "" else {}

    def get_ref_package_for_name(self, name):
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
        str_name_id_package = self.get_obj_ref()
        str_name_id_package[str(name)] = str(id_package)
        self.set_cmd_launch("str_json_name_id_package", json.dumps(str_name_id_package))

    def del_ref_name_for_package(self, name):
        str_name_id_package = self.get_obj_ref()
        try:
            del str_name_id_package[str(name)]
            self.set_cmd_launch(
                "str_json_name_id_package", json.dumps(str_name_id_package)
            )
        except KeyError:
            pass
