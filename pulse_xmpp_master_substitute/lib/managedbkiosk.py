#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import json
import logging
from lib.utils import Env
import traceback

if sys.platform.startswith("darwin"):
    import plyvel
else:
    import bsddb

logger = logging.getLogger()


class manageskioskdb:
    def __init__(self, namebase="kiosk"):
        name_launch_cmd_db = namebase + "launch_cmd_db"
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
        if sys.platform.startswith("darwin"):
            try:
                self.dblaunchcmd = plyvel.DB(
                    self.name_launch_cmd_db, create_if_missing=True
                )
            except Exception:
                logger.error("open pyvel db %s" % self.name_launch_cmd_db)
                os.remove(self.name_launch_cmd_db)
                self.dblaunchcmd = plyvel.DB(
                    self.name_launch_cmd_db, create_if_missing=True
                )
        else:
            try:
                self.dblaunchcmd = bsddb.btopen(self.name_launch_cmd_db, "c")
            except Exception:
                logger.error("open bsddb db %s" % self.name_launch_cmd_db)
                os.remove(self.name_launch_cmd_db)
                self.dblaunchcmd = bsddb.btopen(self.name_launch_cmd_db, "c")

    def closebase(self):
        self.dblaunchcmd.close()

    def bddir(self):
        if sys.platform.startswith("linux"):
            return os.path.join(Env.user_dir(), "BDKiosk")
        elif sys.platform.startswith("win"):
            return os.path.join("c:\\", "progra~1", "Medulla", "var", "tmp", "BDKiosk")
        elif sys.platform.startswith("darwin"):
            return os.path.join("/opt", "Pulse", "BDKiosk")
        else:
            return None

    def set_cmd_launch(self, idpackage, str_cmd_launch):
        idpackage = str(idpackage)
        try:
            self.openbase()
            if sys.platform.startswith("darwin"):
                self.dblaunchcmd.put(bytearray(idpackage), bytearray(str_cmd_launch))
            else:
                self.dblaunchcmd[idpackage] = str_cmd_launch
                self.dblaunchcmd.sync()
        except Exception:
            logger.error("set_cmd_launch %s" % self.name_launch_cmd_db)
            logger.error("\n%s" % (traceback.format_exc()))
        finally:
            self.closebase()

    def get_cmd_launch(self, idpackage):
        idpackage = str(idpackage)
        data = ""
        try:
            self.openbase()
            if sys.platform.startswith("darwin"):
                data = self.dblaunchcmd.get(bytearray(idpackage))
                if data is None:
                    data = ""
            else:
                if str(idpackage) in self.dblaunchcmd:
                    data = self.dblaunchcmd[idpackage]
        except Exception:
            logger.error("get_cmd_launch %s" % self.name_launch_cmd_db)
            logger.error("\n%s" % (traceback.format_exc()))
        finally:
            self.closebase()
        return str(data)

    def del_cmd_launch(self, idpackage):
        idpackage = str(idpackage)
        self.openbase()
        try:
            if sys.platform.startswith("darwin"):
                data = self.dblaunchcmd.delete(bytearray(idpackage))
            else:
                if idpackage in self.dblaunchcmd:
                    del self.dblaunchcmd[idpackage]
                    self.dblaunchcmd.sync()
        except Exception:
            logger.error("del_cmd_launch %s" % self.name_launch_cmd_db)
            logger.error("\n%s" % (traceback.format_exc()))
        finally:
            self.closebase()

    def get_all_obj_launch(self):
        self.openbase()
        try:
            result = {}
            if sys.platform.startswith("darwin"):
                for k, v in self.dblaunchcmd:
                    result[str(k)] = str(v)
            else:
                for k, v in self.dblaunchcmd.iteritems():
                    result[str(k)] = str(v)
        except Exception:
            logger.error("del_cmd_launch %s" % self.name_launch_cmd_db)
            logger.error("\n%s" % (traceback.format_exc()))
        finally:
            self.closebase()
        return result

    def get_all_cmd_launch(self):
        self.openbase()
        result = {}
        try:
            if sys.platform.startswith("darwin"):
                for k, v in self.dblaunchcmd:
                    if str(k) == "str_json_name_id_package":
                        continue
                    result[str(k)] = str(v)
            else:
                for k, v in self.dblaunchcmd.iteritems():
                    if str(k) == "str_json_name_id_package":
                        continue
                    result[str(k)] = str(v)
        except Exception:
            logger.error("get_all_cmd_launch %s" % self.name_launch_cmd_db)
            logger.error("\n%s" % (traceback.format_exc()))
        finally:
            self.closebase()
        return result

    ##########################################################################
    # key "str_json_name_id_package" json string reserved to doing match
    # between name  and idpackage

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
