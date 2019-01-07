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
# file manage_xmppbrowsing.py

import os, sys
import json, re
import logging
from utils import shellcommandtimeout, file_get_content, simplecommand, decode_strconsole, encode_strconsole
import zlib
import base64
logger = logging.getLogger()

class xmppbrowsing:
    """
        Cette class repond au demande faite par mmc sur le file systeme
    """
    def __init__(self, defaultdir = None, rootfilesystem = None):
        """
            :param type: Uses this parameter to give a path abs
            :type defaultdir: string
            :type rootfilesystem :string
            :return: Function init has no return
        """
        self.defaultdir     = None
        self.rootfilesystem = None
        self.dirinfos       = {}
        self.initialisation = 0
        self.hierarchystring = "" # use cache hierarchy
        self.jsonfile=""

        #determination programme et fichier generé pour la hierarchi des dossiers
        if sys.platform.startswith('linux'):
            self.jsonfile = "/tmp/treejson.json"
            self.programmetreejson = os.path.join("/","usr","sbin","pulse-filetree-generator")
        elif sys.platform.startswith('win'):
            self. jsonfile = 'C:\\\\Program Files\\Pulse\\tmp\\treejson.json'
            self. programmetreejson = 'C:\\\\"Program Files"\\Pulse\\bin\\pulse-filetree-generator.exe'
        elif sys.platform.startswith('darwin'):
            self.jsonfile =  "/tmp/treejson.json"
            self.programmetreejson = "/Library/Application Support/Pulse/bin/pulse-filetree-generator"

        if defaultdir is not None:
            self.defaultdir = defaultdir
        if rootfilesystem is not None:
            self.rootfilesystem = rootfilesystem

    def strjsontree(self):
        try:
            if os.path.isfile(self.jsonfile):
                l = decode_strconsole(file_get_content(self.jsonfile))
                return l
            else:
                self.createjsontree()
            l = decode_strconsole(file_get_content(self.jsonfile))
            return l
        except Exception as e:
            logger.error("strjsontree %s"%str(e))
        return  {}

    def createjsontree(self):
        logging.getLogger().debug("Creation hierarchi file")
        cmd ='%s "%s" "%s"'%(self.programmetreejson, self.rootfilesystem, self.jsonfile)
        msg = "Generation tree.json command : [%s] "%cmd
        logging.getLogger().debug("%s : "%cmd)
        obj = simplecommand(cmd)
        if obj['code'] != 0 :
            logger.error(msg)
            return
        logger.debug(msg)

    def listfileindir(self, path_abs_current = None):
        ###path_abs_current
        logging.getLogger().debug("---------------------------------------------------------")
        logging.getLogger().debug("search files and folders list for %s : "%path_abs_current)
        logging.getLogger().debug("---------------------------------------------------------")
        boolhierarchy = False
        if path_abs_current is  None or path_abs_current == "":
            self.initialisation = 0
            self.hierarchystring = ""
            boolhierarchy = True
            pathabs = self.rootfilesystem
            path_abs_current = self.rootfilesystem
        elif path_abs_current.startswith('@'):
            boolhierarchy = True
            self.createjsontree()
            self.initialisation += 1
            pathabs = self.defaultdir
        else:
            dd = path_abs_current.split("/")
            rr=dd[0]
            del dd[0]
            path_abs_current = "/".join(dd)
            self.hierarchystring = ""
            self.initialisation = 0
            if path_abs_current.startswith('/'):
                path_abs_current = path_abs_current[1:]
            pathabs = os.path.join(self.rootfilesystem, path_abs_current)
        try:
            list_files_current = os.walk(pathabs).next();
        except Exception as e:
            list_files_current=[]
            list_files_current.append(pathabs)
            list_files_current.append([])
            list_files_current.append([])
        listfileinfolder = []
        for namefile in list_files_current[2]:
            fichier_and_size = os.path.join(pathabs, namefile)
            listfileinfolder.append((namefile, os.path.getsize(fichier_and_size)))

        self.dirinfos = {
            "path_abs_current" : pathabs,
            "list_dirs_current" : list_files_current[1],
            "list_files_current" : listfileinfolder,
            "parentdir" : os.path.abspath(os.path.join(pathabs, os.pardir)),
            "rootfilesystem" : self.rootfilesystem,
            "defaultdir" : self.defaultdir
        }
        if boolhierarchy:
            self.dirinfos["strjsonhierarchy"] = self.strjsontree()
        return self.dirinfos
