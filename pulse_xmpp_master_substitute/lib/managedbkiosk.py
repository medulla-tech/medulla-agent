#!/usr/bin/env python
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
#
# file : lib/managedbkiosk.py

import sys
import os
import json
import logging
if sys.platform.startswith('darwin'):
    import plyvel
else:
    import bsddb

logger = logging.getLogger()

class manageskioskdb:

    def __init__(self, namebase = "kiosk"):
        name_launch_cmd_db     = namebase + 'launch_cmd_db'
        self.openbool = False
        path_bd = self.bddir()
        if path_bd is not None:
            if not os.path.exists(path_bd):
                os.makedirs(path_bd, mode=0700)
            self.name_launch_cmd_db = os.path.join(path_bd, name_launch_cmd_db)
            if sys.platform.startswith('darwin'):
                if not os.path.isdir(self.name_launch_cmd_db):
                    os.makedirs(self.name_launch_cmd_db, mode=0700)

    def openbase(self):
        if sys.platform.startswith('darwin'):
            self.dblaunchcmd = plyvel.DB(self.name_launch_cmd_db, create_if_missing=True)
        else:
            self.dblaunchcmd = bsddb.btopen(self.name_launch_cmd_db , 'c')

    def closebase(self):
        self.dblaunchcmd.close()

    def bddir(self):
        if sys.platform.startswith('linux'):
            return os.path.join("/", "var" ,"lib","pulse2","BDKiosk")
        elif sys.platform.startswith('win'):
            return os.path.join(os.environ["ProgramFiles"], "Pulse","var","tmp","BDKiosk")
        elif sys.platform.startswith('darwin'):
            return os.path.join("/", "Library", "Application Support", "Pulse", "BDKiosk")
        else:
            return None

    def set_cmd_launch(self, idpackage, str_cmd_launch):
        idpackage = str(idpackage)
        self.openbase()
        if sys.platform.startswith('darwin'):
            self.dblaunchcmd.put(bytearray(idpackage), bytearray(str_cmd_launch))
        else:
            self.dblaunchcmd[idpackage] = str_cmd_launch
            self.dblaunchcmd.sync()
        self.closebase()

    def get_cmd_launch(self, idpackage):
        idpackage = str(idpackage)
        data = ""
        self.openbase()
        if sys.platform.startswith('darwin'):
            data = self.dblaunchcmd.get(bytearray(idpackage))
            if data is None:
                data =""
        else:
            if self.dblaunchcmd.has_key(str(idpackage)):
                data = self.dblaunchcmd[idpackage]
        self.closebase()
        return str(data)

    def del_cmd_launch(self, idpackage):
        idpackage = str(idpackage)
        self.openbase()
        if sys.platform.startswith('darwin'):
            data = self.dblaunchcmd.delete(bytearray(idpackage))
        else:
            if self.dblaunchcmd.has_key(idpackage):
                del self.dblaunchcmd[idpackage]
                self.dblaunchcmd.sync()
        self.closebase()

    def get_all_obj_launch(self):
        self.openbase()
        result = {}
        if sys.platform.startswith('darwin'):
            for k, v in self.dblaunchcmd:
                result[str(k)] = str(v)
        else:
            for k, v in self.dblaunchcmd.iteritems():
                result[str(k)] = str(v)
        self.closebase()
        return result

    def get_all_cmd_launch(self):
        self.openbase()
        result = {}
        if sys.platform.startswith('darwin'):
            for k, v in self.dblaunchcmd:
                if str(k) == "str_json_name_id_package":
                    continue
                result[str(k)] = str(v)
        else:
            for k, v in self.dblaunchcmd.iteritems():
                if str(k) == "str_json_name_id_package":
                    continue
                result[str(k)] = str(v)
        self.closebase()
        return result
    ################################################################################################
    # key "str_json_name_id_package" json string reserved to doing match between name  and idpackage 
    def get_obj_ref(self):
        str_name_idpackage = {}
        strjson = self.get_cmd_launch("str_json_name_id_package")
        if strjson != "":
            str_name_idpackage = json.loads(str(strjson))
        else:
            str_name_idpackage = {}
        return str_name_idpackage

    def get_ref_package_for_name(self, name):
        str_name_idpackage = ""
        strjson = self.get_cmd_launch("str_json_name_id_package")
        if strjson != "":
            str_name_idpackage = json.loads(str(strjson))
            if name  in str_name_idpackage:
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
            self.set_cmd_launch("str_json_name_id_package", json.dumps(str_name_id_package))
        except KeyError:
            pass
