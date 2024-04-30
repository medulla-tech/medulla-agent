#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import logging

if sys.platform.startswith("darwin"):
    import plyvel
else:
    import bsddb3 as bsddb
from lib.utils import Env


logger = logging.getLogger()


class manageschedulerdeploy:
    def __init__(self, namebase="BDtimedeploy"):
        name_basecmd = namebase + "cmddb"
        name_basesession = namebase + "sessiondb"
        self.openbool = False
        path_bd = self.bddir()
        if path_bd is not None:
            if not os.path.exists(path_bd):
                os.makedirs(path_bd, mode=0o700)
            self.name_basesession = os.path.join(path_bd, name_basesession)
            self.name_basecmd = os.path.join(path_bd, name_basecmd)
            if sys.platform.startswith("darwin"):
                if not os.path.isdir(self.name_basesession):
                    os.makedirs(self.name_basesession, mode=0o700)
                if not os.path.isdir(self.name_basecmd):
                    os.makedirs(self.name_basecmd, mode=0o700)

    def openbase(self):
        if sys.platform.startswith("darwin"):
            self.dbcmdscheduler = plyvel.DB(
                self.name_basesession, create_if_missing=True
            )
            self.dbsessionscheduler = plyvel.DB(
                self.name_basecmd, create_if_missing=True
            )
        else:
            self.dbcmdscheduler = bsddb.btopen(self.name_basecmd, "c")
            self.dbsessionscheduler = bsddb.btopen(self.name_basesession, "c")

    def closebase(self):
        self.dbcmdscheduler.close()
        self.dbsessionscheduler.close()

    def bddir(self):
        if sys.platform.startswith("linux"):
            return os.path.join(Env.user_dir(), "BDDeploy")
        elif sys.platform.startswith("win"):
            return os.path.join("c:\\", "progra~1", "Medulla", "var", "tmp", "BDDeploy")
        elif sys.platform.startswith("darwin"):
            return os.path.join("/opt", "Pulse", "var", "tmp", "BDDeploy")
        else:
            return None

    def set_sesionscheduler(self, sessionid, objsession):
        sessionid = str(sessionid)
        self.openbase()
        if sys.platform.startswith("darwin"):
            self.dbsessionscheduler.put(bytearray(sessionid), bytearray(objsession))
        else:
            self.dbsessionscheduler[sessionid] = objsession
            self.dbsessionscheduler.sync()
        self.closebase()

    def get_sesionscheduler(self, sessionid):
        sessionid = str(sessionid)
        data = ""
        self.openbase()
        if sys.platform.startswith("darwin"):
            data = self.dbsessionscheduler.get(bytearray(sessionid))
            if data is None:
                data = ""
        else:
            if str(sessionid) in self.dbsessionscheduler:
                data = self.dbsessionscheduler[sessionid]
        self.closebase()
        return data

    def del_sesionscheduler(self, sessionid):
        data = ""
        sessionid = str(sessionid)
        self.openbase()
        if sys.platform.startswith("darwin"):
            data = self.dbsessionscheduler.delete(bytearray(sessionid))
        else:
            if sessionid in self.dbsessionscheduler:
                del self.dbsessionscheduler[sessionid]
                self.dbsessionscheduler.sync()
        self.closebase()
        return data
