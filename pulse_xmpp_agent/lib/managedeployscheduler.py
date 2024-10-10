#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


import sys
import os
import logging
from lib.utils import Env
from lib.agentconffile import (
    conffilename,
    medullaPath,
    directoryconffile,
    pulseTempDir,
    conffilenametmp,
    rotation_file,
)
import lmdb
from lib.manageDb import ManageDb

logger = logging.getLogger()


class manageschedulerdeploy:
    def __init__(self, namebase="BDtimedeploy"):
        name_basecmd = f"{namebase}cmddb"
        name_basesession = f"{namebase}sessiondb"
        self.openbool = False
        path_bd = self.bddir()
        if path_bd is not None:
            if not os.path.exists(path_bd):
                os.makedirs(path_bd, mode=0o700)
            self.name_basesession = os.path.join(path_bd, name_basesession)
            self.name_basecmd = os.path.join(path_bd, name_basecmd)
            # on del base if name prefix underscore
            self.name_basesessioncorrup = os.path.join(
                path_bd, f"__db.{name_basesession}"
            )
            self.name_basecmdcorrup = os.path.join(path_bd, f"__db.{name_basecmd}")
            if os.path.exists(self.name_basesessioncorrup):
                logger.warning(
                    "Verify integrity of data "
                    "base\n\t%s on ->? %s"
                    % (self.name_basesession, self.name_basesessioncorrup)
                )
            if os.path.exists(self.name_basecmdcorrup):
                logger.warning(
                    "Verify integrity of data "
                    "base\n\t%s on ->? %s"
                    % (self.name_basecmd, self.name_basecmdcorrup)
                )

            if sys.platform.startswith("darwin"):
                if not os.path.isdir(self.name_basesession):
                    os.makedirs(self.name_basesession, mode=0o700)
                if not os.path.isdir(self.name_basecmd):
                    os.makedirs(self.name_basecmd, mode=0o700)

    def bddir(self):
        """
        This function is used to provide the sql file used.
        Returns:
            It returns the path + name of the sql file.
        """
        if sys.platform.startswith("linux"):
            return os.path.join(Env.user_dir(), "BDDeploy")
        elif sys.platform.startswith("win"):
            return os.path.join(medullaPath(), "var", "tmp", "BDDeploy")
        elif sys.platform.startswith("darwin"):
            return os.path.join("/opt", "Pulse", "BDDeploy")
        else:
            return None

    def openbase(self):
        """
        This function is used to open and give acces to the
        database.
        If the database does not exist it will create it.
        And if we fail to read the database, we delete it
        and recreate a new one.
        """
        try:
            self.dbsessionscheduler = lmdb.open(
                self.name_basesession, map_size=10485760
            )
            self.dblaunchcmd = self.dbsessionscheduler.begin(write=True)
        except Exception:
            logger.error(
                f"An error occured while opening the database: {self.name_basesession}"
            )
            os.remove(self.name_basesession)
            self.dbsessionscheduler = lmdb.open(
                self.name_basesession, map_size=10485760
            )
            self.dblaunchcmd = self.dbsessionscheduler.begin(write=True)

        try:
            self.dbcmdscheduler = lmdb.open(self.name_basesession, map_size=10485760)
            self.dblaunchcmd = self.dbcmdscheduler.begin(write=True)
        except Exception:
            logger.error(
                f"An error occured while opening the database: {self.name_basecmd}"
            )
            os.remove(self.name_basecmd)
            self.dbcmdscheduler = lmdb.open(self.name_basesession, map_size=10485760)
            self.dblaunchcmd = self.dbcmdscheduler.begin(write=True)

    def closebase(self):
        """
        This function is used to correctly close the database.
        """
        self.dbcmdscheduler.close()
        self.dbsessionscheduler.close()

    def set_sesionscheduler(self, sessionid, objsession):
        sessionid = str(sessionid)
        try:
            self.openbase()
            self.dbsessionscheduler.put(bytearray(sessionid), bytearray(objsession))
        except Exception as exception_error:
            logger.error(
                "In the function set_sesionscheduler the plugin %s failed with the error: \n %s"
                % (self.name_basesession, exception_error)
            )
        finally:
            self.closebase()

    def get_sesionscheduler(self, sessionid):
        sessionid = str(sessionid)
        data = ""
        try:
            self.openbase()
            data = self.dbsessionscheduler.get(bytearray(sessionid))
            if data is None:
                data = ""
        except Exception as exception_error:
            logger.error(
                "In the function get_sesionscheduler the plugin %s failed with the error: \n %s"
                % (self.name_basesession, exception_error)
            )
        finally:
            self.closebase()
        return data

    def del_sesionscheduler(self, sessionid):
        data = ""
        sessionid = str(sessionid)
        try:
            self.openbase()
            if sys.platform.startswith("darwin"):
                data = self.dbsessionscheduler.delete(bytearray(sessionid))
            elif sessionid in self.dbsessionscheduler:
                del self.dbsessionscheduler[sessionid]
                self.dbsessionscheduler.sync()
            self.closebase()
        except Exception as exception_error:
            logger.error(
                "In the function del_sesionscheduler the plugin %s failed with the error: \n %s"
                % (self.name_basesession, exception_error)
            )
        finally:
            self.closebase()

        return data


class ManageDbScheduler(ManageDb):
    tablename = "scheduler"
    path = os.path.join(medullaPath(), "var", "tmp", "BDDeploy", "scheduler.db")

    def __init__(self):
        super().__init__()
