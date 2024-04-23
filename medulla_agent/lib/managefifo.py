# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import glob
import os
import json
import logging
import time
import traceback

Logger = logging.getLogger()


class fifodeploy:
    def __init__(self):
        # creation de la fifo en fonction des fichiers trouver dans le
        # repertoire fifo
        self.FIFOdeploy = []  # name des file fifo
        self.SESSIONdeploy = {}  # liste des sessions deploy mis en file
        self.dirsavedatafifo = os.path.abspath(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "..", "fifodeploy"
            )
        )
        if not os.path.exists(self.dirsavedatafifo):
            os.makedirs(self.dirsavedatafifo, mode=0o007)
        Logger.debug(f"Manager fifo : {self.dirsavedatafifo}")
        # load les sessions fifos
        # parcoure le repertoire fifo, et charge les fifo dans FIFOdeploy
        # self.loadfifo() #charge fifo for deployement decommente cette line
        # si tu veux reprendre les fifo apres un restart de ARS.
        # cleardirfifo supprime les fifo au redémarage de ARS
        self.cleardirfifo()  # commente cette line cleardirfifo
        # si tu veux reprendre les fifo apres un restart de ARS

    def _InitSessiondeploy(self):
        self.SESSIONdeploy = {}
        suplist = []
        for fifodata in self.FIFOdeploy:
            data = self.readfifo(fifodata)
            if "sessionid" in data:
                self.SESSIONdeploy[data["sessionid"]] = fifodata
            else:
                suplist.append(fifodata)
        for t in suplist:
            self.FIFOdeploy.remove(t)

    def loadfifo(self):
        self.FIFOdeploy = [
            os.path.basename(x)
            for x in glob.glob(os.path.join(self.dirsavedatafifo, "*"))
            if (os.path.isfile(x) and os.path.basename(x).endswith("fifo"))
        ]
        self.FIFOdeploy.sort()
        self._InitSessiondeploy()
        return self.SESSIONdeploy

    def checking_deploy_slot_outdoor(self):
        try:
            removefilefifo = []
            Logger.debug("Verify slot for fifo")
            sessionterminate = []
            for fifodata in self.FIFOdeploy:
                data = self.readfifo(fifodata)
                if data["enddate"] < time.time():
                    Logger.debug(f"fifo file of deployment slot has passed.{fifodata}")
                    sessionterminate.append(data["sessionid"])
                    removefilefifo.append(fifodata)
                else:
                    Logger.debug(f"fifo waitting for deploy.{fifodata}")
                if sessionterminate:
                    Logger.debug(
                        f"return abandons the deployment of the session the deployment slot has passed.{sessionterminate}"
                    )
        except Exception as e:
            Logger.error("\n%s" % (traceback.format_exc()))
        return sessionterminate

    def cleardirfifo(self):
        self.FIFOdeploy = [
            os.path.basename(x)
            for x in glob.glob(os.path.join(self.dirsavedatafifo, "*"))
            if (os.path.isfile(x) and os.path.basename(x).endswith("fifo"))
        ]
        for fifodata in self.FIFOdeploy:
            pathnamefile = os.path.join(self.dirsavedatafifo, fifodata)
            if os.path.isfile(pathnamefile):
                os.remove(pathnamefile)
                Logger.debug(f"file {pathnamefile} in Manager fifo is cleanned")
        self.FIFOdeploy = []

    def getcount(self):
        return len(self.FIFOdeploy)

    def setfifo(self, datajson, priority=None):
        newfilefifo = f"{str(time.time())}.fifo"
        pathnamefile = os.path.join(self.dirsavedatafifo, newfilefifo)
        with open(pathnamefile, "w") as outfilejson:
            json.dump(datajson, outfilejson, indent=4)
        if priority is not None and priority == "high":
            self.FIFOdeploy.insert(0, newfilefifo)
            Logger.debug(f"set fifo high file {newfilefifo}  fifo {self.FIFOdeploy}")
        else:
            self.FIFOdeploy.append(newfilefifo)
            Logger.debug(f"set fifo low file {newfilefifo}  fifo {self.FIFOdeploy}")
        self.SESSIONdeploy[datajson["sessionid"]] = newfilefifo

    def getfifo(self):
        """
        fifo shift
            unstacking at the top of the list
            return descriptor déployement
            rq: le deploy descriptor file is deleted
        """
        if self.getcount() == 0:
            return {}
        if len(self.FIFOdeploy) == 0:
            self.SESSIONdeploy = {}
            return {}
        firstfileinput = self.FIFOdeploy.pop(0)
        pathnamefile = os.path.join(self.dirsavedatafifo, firstfileinput)
        if not os.path.isfile(pathnamefile):
            return {}
        try:
            fichier_json = open(pathnamefile, "r")
            with fichier_json as fichier:
                data = json.load(fichier)  # load décode un fichier json
            # add dans ressource ce transfert.
            # self.currentresource.add(data['sessionid'])
            os.remove(pathnamefile)
            try:
                del self.SESSIONdeploy[data["sessionid"]]
            except Exception as e:
                Logger.error(f"del session in FIFO : {str(e)}")
            return data
        except Exception as e:
            if os.path.isfile(pathnamefile):
                Logger.error(f"del fichier fifo on error json{pathnamefile}")
                os.remove(pathnamefile)
            Logger.error(
                "look file %s in Manager fifo :\n[%s]" % (pathnamefile, str(e))
            )
            Logger.error("\n%s" % (traceback.format_exc()))
            return {}

    def delsessionfifo(self, sessionid):
        Logger.debug(f"del session id : {sessionid}")
        try:
            namefile = self.SESSIONdeploy[sessionid]
            try:
                self.FIFOdeploy.remove(self.SESSIONdeploy[sessionid])
            except ValueError as e:
                Logger.error("file missing for remove fifo" % (str(e)))
            del self.SESSIONdeploy[sessionid]
            pathnamefile = os.path.join(self.dirsavedatafifo, namefile)
            os.remove(pathnamefile)
        except KeyError:
            Logger.warning(f"the session {sessionid} no longer exists.")
        except Exception as e:
            Logger.error(f"del session fifo {sessionid} err : [{str(e)}]")
            Logger.error("\n%s" % (traceback.format_exc()))

    def readfifo(self, namefifo):
        """
        return deploy descriptor data from file descriptor
        """
        if self.getcount() == 0:
            return {}
        pathnamefile = os.path.join(self.dirsavedatafifo, namefifo)
        if not os.path.isfile(pathnamefile):
            Logger.error(f"file {pathnamefile} in Manager fifo is missing")
            return {}
        try:
            fichier_json = open(pathnamefile, "r")
            with fichier_json as fichier:
                data = json.load(fichier)  # load décode un fichier json
            return data
        except Exception as e:
            Logger.error(
                "look file %s in Manager fifo :\n[%s]" % (pathnamefile, str(e))
            )
            if os.path.isfile(pathnamefile):
                Logger.error(f"del fichier fifo on error json{pathnamefile}")
                os.remove(pathnamefile)
            return {}

    def displayfifo(self):
        for fifodata in self.FIFOdeploy:
            print(self.readfifo(fifodata))
            Logger.info(f"{self.readfifo(fifodata)}")

    def prioritydeploy(self, sessionid):
        """
        an id session is passed in parameter.
        This function passes the deployment of this priority session.
        """
        # search dans la liste si cette id existe.
        if sessionid in self.SESSIONdeploy:
            filefifo = self.SESSIONdeploy[sessionid]
            self.FIFOdeploy.remove(filefifo)
            self.FIFOdeploy.insert(0, filefifo)
            return True
        else:
            return False
