# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import glob
import os
import json
import logging
import time
import traceback


class fifodeploy:
    def __init__(self):
        # creation de la fifo en fonction des fichiers trouver dans le
        # repertoire fifo
        self.FIFOdeploy = []
        self.dirsavedatafifo = os.path.abspath(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "..", "fifodeploy"
            )
        )
        if not os.path.exists(self.dirsavedatafifo):
            os.makedirs(self.dirsavedatafifo, mode=0o007)
        logging.getLogger().debug("Manager fifo : %s" % self.dirsavedatafifo)
        # load les sessions fifos
        # parcoure le repertoire fifo, et charge les fifo dans FIFOdeploy
        self.loadfifo()

    def loadfifo(self):
        self.FIFOdeploy = [
            os.path.basename(x)
            for x in glob.glob(os.path.join(self.dirsavedatafifo, "*"))
            if (os.path.isfile(x) and os.path.basename(x).endswith("fifo"))
        ]
        self.FIFOdeploy.sort()

    def getcount(self):
        return len(self.FIFOdeploy)

    def setfifo(self, datajson):
        newfilefifo = str(time.time()) + ".fifo"
        pathnamefile = os.path.join(self.dirsavedatafifo, newfilefifo)
        with open(pathnamefile, "w") as outfilejson:
            json.dump(datajson, outfilejson, indent=4)
        self.FIFOdeploy.append(newfilefifo)

    def getfifo(self):
        if self.getcount() == 0:
            return {}
        firstfileinput = self.FIFOdeploy.pop(0)
        pathnamefile = os.path.join(self.dirsavedatafifo, firstfileinput)
        try:
            fichier_json = open(pathnamefile, "r")
            with fichier_json as fichier:
                data = json.load(fichier)  # load décode un fichier json
            os.remove(pathnamefile)
            return data
        except Exception as e:
            logging.getLogger().warning(
                "look file %s in Manager fifo :\n[%s]" % (pathnamefile, str(e))
            )
            logging.getLogger().error("\n%s" % (traceback.format_exc()))
            return {}

    def readfifo(self, namefifo):
        if self.getcount() == 0:
            return {}
        pathnamefile = os.path.join(self.dirsavedatafifo, namefifo)
        if not os.path.isfile(pathnamefile):
            logging.getLogger().error(
                "file %s in Manager fifo is missing" % (pathnamefile)
            )
            return {}
        try:
            fichier_json = open(pathnamefile, "r")
            with fichier_json as fichier:
                data = json.load(fichier)  # load décode un fichier json
            return data
        except Exception as e:
            logging.getLogger().warning(
                "look file %s in Manager fifo :\n[%s]" % (pathnamefile, str(e))
            )
            logging.getLogger().error("\n%s" % (traceback.format_exc()))
            return {}

    def displayfifo(self):
        for fifodata in self.FIFOdeploy:
            print(self.readfifo(fifodata))
