# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sys
import logging
from lib.utils import file_get_content, simplecommand, decode_strconsole
import math
import traceback

logger = logging.getLogger()


class xmppbrowsing:
    """
    Cette class repond au demande faite par mmc sur le file systeme
    """

    def __init__(self, defaultdir=None, rootfilesystem=None, objectxmpp=None):
        """
        :param type: Uses this parameter to give a path abs
        :type defaultdir: string
        :type rootfilesystem :string
        :return: Function init has no return
        """
        self.objectxmpp = objectxmpp
        self.defaultdir = None
        self.rootfilesystem = None
        self.dirinfos = {}
        self.initialisation = 0
        self.hierarchystring = ""  # use cache hierarchy
        self.jsonfile = ""
        if objectxmpp is not None:
            self.excludelist = objectxmpp.config.excludelist
        # determination programme et fichier generé pour la hierarchi des
        # dossiers
        if sys.platform.startswith("linux"):
            self.jsonfile = os.path.join("/", "tmp", "treejson.json")
            self.programmetreejson = os.path.join(
                "/", "usr", "sbin", "pulse-filetree-generator"
            )
        elif sys.platform.startswith("win"):
            self.jsonfile = os.path.join(
                "c:\\", "progra~1", "Medulla", "tmp", "treejson.json"
            )
            self.programmetreejson = os.path.join(
                "c:\\",
                "progra~1",
                "Pulse",
                "bin",
                "pulse-filetree-generator.exe",
            )
        elif sys.platform.startswith("darwin"):
            self.jsonfile = os.path.join("/opt", "Pulse", "tmp", "treejson.json")
            self.programmetreejson = os.path.join(
                "/opt", "Pulse", "bin", "pulse-filetree-generator"
            )

        if defaultdir is not None:
            self.defaultdir = defaultdir
        if rootfilesystem is not None:
            self.rootfilesystem = rootfilesystem

    def strjsontree(self):
        try:
            if sys.platform.startswith("win"):
                cont = file_get_content(
                    os.path.join("c:\\", "progra~1", "Medulla", "tmp", "treejson.json")
                )
                l = decode_strconsole(cont)
                return l
            else:
                return {}
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("strjsontree %s" % str(e))
        return {}

    def createjsontree(self):
        logging.getLogger().debug("Creation hierarchi file")
        if sys.platform.startswith("win"):
            cmd = "%s %s %s" % (
                self.programmetreejson,
                self.rootfilesystem,
                self.jsonfile,
            )
        else:
            cmd = "%s -r '%s' -o \"%s\"" % (
                self.programmetreejson,
                self.rootfilesystem,
                self.jsonfile,
            )
        msg = "Generation tree.json command : [%s] " % cmd
        logging.getLogger().debug("%s : " % cmd)
        obj = simplecommand(cmd)
        if obj["code"] != 0:
            logger.error(obj["result"])
            if self.objectxmpp is not None:
                self.objectxmpp.xmpplog(
                    "Error generating tree for machine %s [command :%s]"
                    % (self.objectxmpp.boundjid.bare, cmd),
                    type="noset",
                    sessionname="",
                    priority=0,
                    action="xmpplog",
                    who=self.objectxmpp.boundjid.bare,
                    how="Remote",
                    why="",
                    module="Error| Notify | browsing",
                    fromuser="",
                    touser="",
                )
            return
        if self.objectxmpp is not None:
            self.objectxmpp.xmpplog(
                "Generating tree for machine %s [command :%s]"
                % (self.objectxmpp.boundjid.bare, cmd),
                type="noset",
                sessionname="",
                priority=0,
                action="xmpplog",
                who=self.objectxmpp.boundjid.bare,
                how="Remote",
                why="",
                module="Error| Notify | browsing",
                fromuser="",
                touser="",
            )
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
        if sys.platform.startswith("win"):
            path = path.replace("/", "\\")
            path = path.replace("\\\\", "\\")
            path = path.replace('"', "")
        for x in os.listdir(path):
            name = os.path.join(path, x)
            if os.path.isfile(name):
                filesinfolder.append((x, self._convert_size(os.path.getsize(name))))
            else:
                foldersinfloder.append(x)
        return foldersinfloder, filesinfolder

    def listfileindir(self, path_abs_current=None):
        # path_abs_current
        logging.getLogger().debug(
            "---------------------------------------------------------"
        )
        logging.getLogger().debug(
            "search files and folders list for %s : " % path_abs_current
        )
        logging.getLogger().debug(
            "---------------------------------------------------------"
        )
        boolhierarchy = False
        if path_abs_current is None or path_abs_current == "":
            self.initialisation = 0
            self.hierarchystring = ""
            boolhierarchy = True
            pathabs = self.rootfilesystem
            path_abs_current = self.rootfilesystem
        elif path_abs_current.startswith("@"):
            boolhierarchy = True
            self.createjsontree()
            self.initialisation += 1
            pathabs = self.defaultdir
        else:
            dd = path_abs_current.split("/")
            rr = dd[0]
            del dd[0]
            path_abs_current = "/".join(dd)
            self.hierarchystring = ""
            self.initialisation = 0
            if path_abs_current.startswith("/"):
                path_abs_current = path_abs_current[1:]
            pathabs = os.path.join(self.rootfilesystem, path_abs_current)
            pathabs = pathabs.replace("C:", "c:")
        try:
            list_files_current_dirs, list_files_current_files = self._listdirfile(
                pathabs
            )
        except Exception as e:
            list_files_current_dirs = []
            list_files_current_files = []
        display_only_folder_no_nexclude = []
        for k in list_files_current_dirs:
            if not os.path.join(pathabs, k) in self.excludelist:
                display_only_folder_no_nexclude.append(k)
        self.dirinfos = {
            "path_abs_current": pathabs,
            "list_dirs_current": display_only_folder_no_nexclude,
            "list_files_current": list_files_current_files,
            "parentdir": os.path.abspath(os.path.join(pathabs, os.pardir)),
            "rootfilesystem": self.rootfilesystem,
            "defaultdir": self.defaultdir,
        }
        if boolhierarchy:
            self.dirinfos["strjsonhierarchy"] = self.strjsontree()
        return self.dirinfos
