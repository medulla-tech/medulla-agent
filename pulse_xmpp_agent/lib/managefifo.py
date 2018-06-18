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
        self.FIFOdeploy = []
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

    def loadfifo(self):
        self.FIFOdeploy = [
            os.path.basename(x) for x in glob.glob(
                os.path.join(
                    self.dirsavedatafifo,
                    "*")) if (
                os.path.isfile(x) and os.path.basename(x).endswith('fifo'))]
        self.FIFOdeploy.sort()

    def getcount(self):
        return len(self.FIFOdeploy)

    def setfifo(self, datajson):
        newfilefifo = str(time.time())+'.fifo'
        pathnamefile = os.path.join(self.dirsavedatafifo, newfilefifo)
        with open(pathnamefile, 'w') as outfilejson:
            json.dump(datajson, outfilejson, indent = 4)
        self.FIFOdeploy.append(newfilefifo)

    def getfifo(self):
        if self.getcount() == 0:
            return {}
        firstfileinput  = self.FIFOdeploy.pop(0)
        pathnamefile = os.path.join(self.dirsavedatafifo, firstfileinput)
        try:
            fichier_json = open( pathnamefile, 'r')
            with fichier_json as fichier:
                data = json.load(fichier)      # load décode un fichier json
            os.remove(pathnamefile)
            return data
        except Exception as  e:
            logging.getLogger().warning("look file %s in Manager fifo :\n[%s]" % (pathnamefile, str(e)))
            traceback.print_exc(file=sys.stdout)
            return {}

    def readfifo(self, namefifo):
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
            logging.getLogger().warning("look file %s in Manager fifo :\n[%s]" % (pathnamefile, str(e)))
            traceback.print_exc(file=sys.stdout)
            return {}

    def displayfifo(self):
        for fifodata in self.FIFOdeploy:
            print self.readfifo(fifodata)
