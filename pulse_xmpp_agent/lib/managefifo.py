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
        self.dirsavedatafifo = os.path.abspath(os.path.join(
            os.path.dirname(
                os.path.realpath(__file__)),
            "..",
            "fifodeploy"))
        if not os.path.exists(self.dirsavedatafifo):
            os.makedirs(self.dirsavedatafifo, mode=0o007)
        Logger.debug("Manager fifo : %s" % self.dirsavedatafifo)
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
            os.path.basename(x) for x in glob.glob(
                os.path.join(
                    self.dirsavedatafifo,
                    "*")) if (
                os.path.isfile(x) and os.path.basename(x).endswith('fifo'))]
        self.FIFOdeploy.sort()
        self._InitSessiondeploy()
        return self.SESSIONdeploy

    def checking_deploy_slot_outdoor(self):
        try:
            sessionterminate = []
            removefilefifo = []
            Logger.debug("Verify slot for fifo")
            for fifodata in self.FIFOdeploy:
                data = self.readfifo(fifodata)
                if data['enddate'] < time.time():
                    Logger.debug(
                        "fifo file of deployment slot has passed.%s" %
                        (fifodata))
                    sessionterminate.append(data['sessionid'])
                    removefilefifo.append(fifodata)
                else:
                    Logger.debug("fifo waitting for deploy.%s" % (fifodata))
                    pass
                if len(sessionterminate) > 0:
                    Logger.debug(
                        "return abandons the deployment of the session "
                        "the deployment slot has passed.%s" %
                        (sessionterminate))
        except Exception as e:
            Logger.error("\n%s" % (traceback.format_exc()))
        return sessionterminate

    def cleardirfifo(self):
        self.FIFOdeploy = [
            os.path.basename(x) for x in glob.glob(
                os.path.join(
                    self.dirsavedatafifo,
                    "*")) if (
                os.path.isfile(x) and os.path.basename(x).endswith('fifo'))]
        for fifodata in self.FIFOdeploy:
            pathnamefile = os.path.join(self.dirsavedatafifo, fifodata)
            if os.path.isfile(pathnamefile):
                os.remove(pathnamefile)
                Logger.debug(
                    "file %s in Manager fifo is cleanned" %
                    (pathnamefile))
        self.FIFOdeploy = []

    def getcount(self):
        return len(self.FIFOdeploy)

    def setfifo(self, datajson, priority=None):
        newfilefifo = str(time.time()) + '.fifo'
        pathnamefile = os.path.join(self.dirsavedatafifo, newfilefifo)
        with open(pathnamefile, 'w') as outfilejson:
            json.dump(datajson, outfilejson, indent=4)
        if priority is not None and priority == "high":
            self.FIFOdeploy.insert(0, newfilefifo)
            Logger.debug(
                "set fifo high file %s  fifo %s" %
                (newfilefifo, self.FIFOdeploy))
        else:
            self.FIFOdeploy.append(newfilefifo)
            Logger.debug(
                "set fifo low file %s  fifo %s" %
                (newfilefifo, self.FIFOdeploy))
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
            fichier_json = open(pathnamefile, 'r')
            with fichier_json as fichier:
                data = json.load(fichier)      # load décode un fichier json
            # add dans ressource ce transfert.
            # self.currentresource.add(data['sessionid'])
            os.remove(pathnamefile)
            try:
                del self.SESSIONdeploy[data['sessionid']]
            except Exception as e:
                Logger.error("del session in FIFO : %s" % str(e))
            return data
        except Exception as e:
            if os.path.isfile(pathnamefile):
                Logger.error(
                    "del fichier fifo on error json%s" %
                    (pathnamefile))
                os.remove(pathnamefile)
            Logger.error(
                "look file %s in Manager fifo :\n[%s]" %
                (pathnamefile, str(e)))
            Logger.error("\n%s" % (traceback.format_exc()))
            return {}

    def delsessionfifo(self, sessionid):
        Logger.debug("del session id : %s" % sessionid)
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
            Logger.warning("the session %s no longer exists." % sessionid)
        except Exception as e:
            Logger.error(
                "del session fifo %s err : [%s]" %
                (sessionid, str(e)))
            Logger.error("\n%s" % (traceback.format_exc()))
            pass

    def readfifo(self, namefifo):
        """
            return deploy descriptor data from file descriptor
        """
        if self.getcount() == 0:
            return {}
        pathnamefile = os.path.join(self.dirsavedatafifo, namefifo)
        if not os.path.isfile(pathnamefile):
            Logger.error("file %s in Manager fifo is missing" % (pathnamefile))
            return {}
        try:
            fichier_json = open(pathnamefile, 'r')
            with fichier_json as fichier:
                data = json.load(fichier)      # load décode un fichier json
            return data
        except Exception as e:
            Logger.error(
                "look file %s in Manager fifo :\n[%s]" %
                (pathnamefile, str(e)))
            # Logger.error("\n%s"%(traceback.format_exc()))
            if os.path.isfile(pathnamefile):
                Logger.error(
                    "del fichier fifo on error json%s" %
                    (pathnamefile))
                os.remove(pathnamefile)
            return {}

    def displayfifo(self):
        for fifodata in self.FIFOdeploy:
            print(self.readfifo(fifodata))
            Logger.info("%s" % (self.readfifo(fifodata)))

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
