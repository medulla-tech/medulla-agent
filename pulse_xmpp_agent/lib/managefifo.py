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
import os, sys
import json
import logging
import time
import traceback

class fifodeploy:
    def __init__(self):
        #creation de la fifo en fonction des fichiers trouver dans le repertoire fifo
        self.FIFOdeploy = [] # name des file fifo
        self.SESSIONdeploy = {} # liste des sessions deploy mis en file
        self.dirsavedatafifo = os.path.abspath(os.path.join(
            os.path.dirname(
                os.path.realpath(__file__)),
            "..",
            "fifodeploy"))
        if not os.path.exists(self.dirsavedatafifo):
            os.makedirs(self.dirsavedatafifo, mode=0o007)
        logging.getLogger().debug("Manager fifo : %s" % self.dirsavedatafifo)
        # load les sessions fifos
        # parcoure le repertoire fifo, et charge les fifo dans FIFOdeploy
        self.loadfifo()

    def _InitSessiondeploy(self):
        self.SESSIONdeploy = {}
        for fifodata in self.FIFOdeploy:
            data = self.readfifo(fifodata)
            self.SESSIONdeploy[data["sessionid"]] = fifodata

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

    def getcount(self):
        return len(self.FIFOdeploy)

    def setfifo(self, datajson, priority = None):
        newfilefifo = str(time.time())+'.fifo'
        pathnamefile = os.path.join(self.dirsavedatafifo, newfilefifo)
        with open(pathnamefile, 'w') as outfilejson:
            json.dump(datajson, outfilejson, indent = 4)
        if priority is not None and priority == "high":
            self.FIFOdeploy.insert(0, newfilefifo)
            logging.getLogger().debug("set fifo high file %s  fifo %s"%(newfilefifo,self.FIFOdeploy))
        else:
            self.FIFOdeploy.append(newfilefifo)
            logging.getLogger().debug("set fifo low file %s  fifo %s"%(newfilefifo,self.FIFOdeploy))
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
        firstfileinput  = self.FIFOdeploy.pop(0)
        pathnamefile = os.path.join(self.dirsavedatafifo, firstfileinput)
        try:
            fichier_json = open( pathnamefile, 'r')
            with fichier_json as fichier:
                data = json.load(fichier)      # load décode un fichier json
            #add dans ressource ce transfert.
            #self.currentresource.add(data['sessionid'])
            os.remove(pathnamefile)
            try:
                del self.SESSIONdeploy[data['sessionid']]
            except Exception as  e:
                logging.getLogger().error("del session in FIFO : %s"%str(e))
            return data
        except Exception as  e:
            logging.getLogger().error("look file %s in Manager fifo :\n[%s]" % (pathnamefile, str(e)))
            traceback.print_exc(file=sys.stdout)
            return {}

    def readfifo(self, namefifo):
        """
            return deploy descriptor data from file descriptor
        """
        if self.getcount() == 0:
            return {}
        pathnamefile = os.path.join(self.dirsavedatafifo, namefifo)
        if not os.path.isfile(pathnamefile):
            logging.getLogger().error("file %s in Manager fifo is missing" % (pathnamefile))
            return {}
        try:
            fichier_json = open( pathnamefile, 'r')
            with fichier_json as fichier:
                data = json.load(fichier)      # load décode un fichier json
            return data
        except Exception as  e:
            logging.getLogger().error("look file %s in Manager fifo :\n[%s]" % (pathnamefile, str(e)))
            traceback.print_exc(file=sys.stdout)
            return {}

    def displayfifo(self):
        for fifodata in self.FIFOdeploy:
            print self.readfifo(fifodata)

    def prioritydeploy(self, sessionid):
        """
            an id session is passed in parameter.
            This function passes the deployment of this priority session.
        """
        #search dans la liste si cette id existe.
        if sessionid in self.SESSIONdeploy:
            filefifo = self.SESSIONdeploy[sessionid]
            self.FIFOdeploy.remove(filefifo)
            self.FIFOdeploy.insert(0, filefifo)
            return True
        else:
            return False
