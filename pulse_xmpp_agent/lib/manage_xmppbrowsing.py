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
import math

logger = logging.getLogger()

class xmppbrowsing:
    """
        Cette class repond au demande faite par mmc sur le file systeme
    """
    def __init__(self, defaultdir = None, rootfilesystem = None, objectxmpp = None):
        """
            :param type: Uses this parameter to give a path abs
            :type defaultdir: string
            :type rootfilesystem :string
            :return: Function init has no return
        """
        self.objectxmpp = objectxmpp
        self.defaultdir     = None
        self.rootfilesystem = None
        self.dirinfos       = {}
        self.initialisation = 0
        self.hierarchystring = "" # use cache hierarchy
        self.jsonfile=""
        if objectxmpp != None:
            self.excludelist =  objectxmpp.config.excludelist
        #determination programme et fichier generé pour la hierarchi des dossiers
        if sys.platform.startswith('linux'):
            self.jsonfile = "/tmp/treejson.json"
            self.programmetreejson = os.path.join("/","usr","sbin","pulse-filetree-generator")
        elif sys.platform.startswith('win'):
            self. jsonfile = 'C:\\\\"Program Files"\\Pulse\\tmp\\treejson.json'
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
            self.jsonfile = self.jsonfile.replace("/","\\");
            self.jsonfile = self.jsonfile.replace("\\\\","\\");
            self.jsonfile = self.jsonfile.replace("\"","");
            if os.path.isfile(self.jsonfile):
                cont = file_get_content(self.jsonfile)
                l = decode_strconsole(cont)
                return l
            else:
                self.createjsontree()
            l = decode_strconsole(file_get_content(self.jsonfile))
            return l
        except Exception as e:            logger.error("strjsontree %s"%str(e))
        return  {}

    def createjsontree(self):
        logging.getLogger().debug("Creation hierarchi file")
        if sys.platform.startswith('win'):
            cmd ='%s %s %s'%(self.programmetreejson,self.rootfilesystem, self.jsonfile)
        else:
            cmd ='%s -r \'%s\' -o "%s"'%(self.programmetreejson, self.rootfilesystem, self.jsonfile)
        msg = "Generation tree.json command : [%s] "%cmd
        logging.getLogger().debug("%s : "%cmd)
        obj = simplecommand(cmd)
        if obj['code'] != 0 :
            logger.error(obj['result'])
            if self.objectxmpp != None:
                self.objectxmpp.xmpplog("error generate tree for machine %s [cmd :%s]"%(self.objectxmpp.boundjid.bare,
                                                                                        cmd),
                                        type = 'noset',
                                        sessionname = '',
                                        priority = 0,
                                        action = "",
                                        who = self.objectxmpp.boundjid.bare,
                                        how = "Remote",
                                        why = "",
                                        module = "Error| Notify | browsing",
                                        fromuser = "",
                                        touser = "")
            return
        if self.objectxmpp != None:
                self.objectxmpp.xmpplog("generate tree for machine %s [cmd :%s]"%(self.objectxmpp.boundjid.bare,
                                                                                  cmd),
                                        type = 'noset',
                                        sessionname = '',
                                        priority = 0,
                                        action = "",
                                        who = self.objectxmpp.boundjid.bare,
                                        how = "Remote",
                                        why = "",
                                        module = "Error| Notify | browsing",
                                        fromuser = "",
                                        touser = "")
        logger.debug(msg)

    def _convert_size(self, size_bytes):
        if size_bytes == 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return "%s %s" % (s, size_name[i])

    def _listdirfile(self, path):
        filesinfolder = []
        foldersinfloder = []
        if sys.platform.startswith('win'):
            path = path.replace("/","\\");
            path = path.replace("\\\\","\\");
            path = path.replace("\"","");
        for x in os.listdir(path):
            name = os.path.join(path, x)
            if os.path.isfile(name):
                filesinfolder.append((x, self._convert_size(os.path.getsize(name))))
            else:
                foldersinfloder.append(x)
        return foldersinfloder, filesinfolder

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
            pathabs = pathabs.replace("C:", "c:");
        try:
            list_files_current_dirs, list_files_current_files = self._listdirfile(pathabs)
        except Exception as e:
            list_files_current_dirs = []
            list_files_current_files = []
        display_only_folder_no_nexclude = []
        for k in list_files_current_dirs:
            if not (os.path.join(pathabs, k) in self.excludelist):
                display_only_folder_no_nexclude.append(k)
        self.dirinfos = {
            "path_abs_current" : pathabs,
            "list_dirs_current" : display_only_folder_no_nexclude,
            "list_files_current" : list_files_current_files,
            "parentdir" : os.path.abspath(os.path.join(pathabs, os.pardir)),
            "rootfilesystem" : self.rootfilesystem,
            "defaultdir" : self.defaultdir
        }
        if boolhierarchy:
            self.dirinfos["strjsonhierarchy"] = self.strjsontree()
        return self.dirinfos
