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


logger = logging.getLogger()


class FileSystem():
    """
        cette class transforme une liste de fichiers en une hierarchie de fichier.
        la function : struct_all_children renvoi une chaine json utilisable avec jstree. plugin jquery.
    """
    def __init__(self, filePath=None, keyfile = "text", keychild = "children"):
        self.children = []
        self.keyfile = keyfile
        self.keychild = keychild
        if filePath != None:
            try:
                if sys.platform.startswith('win'):
                    self.name, child = filePath.split("\\", 1)
                else: #'linux' and 'darwin' separator is /
                    self.name, child = filePath.split("/", 1)
                self.children.append(FileSystem(child))
            except (ValueError):
                self.name = filePath

    def addChild(self, filePath):
        try:
            if sys.platform.startswith('win'): 
                thisLevel, nextLevel = filePath.split("\\", 1)
            else:
                thisLevel, nextLevel = filePath.split("/", 1)
            try:
                if thisLevel == self.name:
                    if sys.platform.startswith('win'): 
                        thisLevel, nextLevel = nextLevel.split("\\", 1)
                    else:
                        thisLevel, nextLevel = nextLevel.split("/", 1)
            except (ValueError):
                self.children.append(FileSystem(nextLevel))
                return
            #for child in self.children:
                #if thisLevel == child.name:
                    #child.addChild(nextLevel)
                    #return
            self.children.append(FileSystem(thisLevel))
            for child in self.children:
                if thisLevel == child.name:
                    child.addChild(nextLevel)
                    return
            #self.children.append(FileSystem(nextLevel))
        except (ValueError):
            self.children.append(FileSystem(filePath))

    def getChildren(self):
        return self.children

    def printAllChildren(self, depth = -1):
        depth += 1
        print "\t"*depth + '"' + self.keyfile + '"' + " : "+ self.name
        if len(self.children) > 0:
            print "\t"*depth +"{ "+'"' + self.keychild +'"' + ":"
            for child in self.children:
                child.printAllChildren(depth)
            print "\t"*depth + "}"

    def struct_all_children(self, depth = -1, a = ""):
        depth += 1
        a = a + "\t"*depth + "{ \"" +self.keyfile + "\" : \""+ self.name + "\","
        if len(self.children) > 0:
            a = a + "\n\t"*depth +"  \"" + self.keychild + "\" : [" + "\n"
            for child in self.children:
                a = child.struct_all_children(depth, a = a)
            a = a + "\t"*depth + "  ]"
        #a = a + "\t"*(depth) + "},\n"
        a = a + "},\n"
        return a

    def makeDict(self):
        if len(self.children) > 0:
            dictionary = {self.name:[]}
            for child in self.children:
                print child
                dictionary[self.name].append(child.makeDict())
            return dictionary
        else:
            return self.name

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
        self.hierarchy = []
        self.initialisation = 0
        self.hierarchystring = ""
        if defaultdir is not None:
            self.defaultdir = defaultdir
        if rootfilesystem is not None:
            self.rootfilesystem = rootfilesystem
            self.hierarchy = self.search_hierarchy(self.rootfilesystem)
        self.listfileindir()


    def search_hierarchy(self, dossiername):
        result = []
        for dossier, sous_dossiers, fichiers in os.walk(dossiername):
            #firstcaractere = ord(dossier[0])
            #if firstcaractere in range(65, 91) or firstcaractere in range(97, 123):
                #dossier = dossier[2:]
            if dossier[1] == ":":
                dossier = dossier[2:]
            #dossier = dossier.replace("C:","")
            dossier = dossier.replace("\\\\","\\")
            if dossier.startswith("\\") or dossier.startswith("/"):
                dossier = dossier[1:]
            result.append(dossier)
            for fichier in fichiers:
                result.append(os.path.join(dossier))
        result=set(result)
        result=list(result)
        result.sort()
        return result

    def clean_json(self, string):
        string = re.sub(",[ \t\r\n]+}", "}", string)
        string = re.sub(",[ \t\r\n]+\]", "]", string)
        return string

    def listfileindir(self, path_abs_current = None):
        logging.getLogger().debug("list file next path %s"%path_abs_current)
        boolhierarchy = False;
        if path_abs_current is  None or path_abs_current == "":
            self.initialisation = 0
            self.hierarchystring = ""
            boolhierarchy = True;
            pathabs = self.rootfilesystem
        elif path_abs_current == "@":
            self.initialisation += 1
            pathabs = self.defaultdir
            boolhierarchy = True;
        else:
            self.hierarchystring = ""
            self.initialisation = 0
            pathabs = os.path.join(self.rootfilesystem, path_abs_current)
        if  not os.path.isdir(pathabs):
            logger.error("Configuration error : folder does not exist\n[browserfile]\ndefaultdir = %s\nrootfilesystem = %s"%(self.defaultdir, self.rootfilesystem))
            return {}
        list_files_current = os.walk(pathabs).next();
        listfileinfolder =[]
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
            if self.initialisation == 2:
                logging.getLogger().debug("tree view in cache")
                self.dirinfos["strjsonhierarchy"] = self.hierarchystring
                return self.dirinfos
            logging.getLogger().debug("Geration tree view")
            self.hierarchy = self.search_hierarchy(self.rootfilesystem)
            myFiles = FileSystem(self.hierarchy[0])
            for record in self.hierarchy[1:]:
                myFiles.addChild(record)
            #print myFiles.makeDict()
            pp = myFiles.struct_all_children()
            eee = eval (pp)
            if "children" in eee[0]:
                self.deldoublon(eee[0])
            pp = json.dumps(eee[0])
            self.dirinfos["strjsonhierarchy"] = pp
            if self.initialisation == 1:
                self.hierarchystring = pp
        return self.dirinfos

    def deldoublon(self, obj):
        pass
        result=[]
        zz=[]
        if "children" in obj:
            k1 = list(obj['children'])
            for y in k1:
                if not y['text'] in zz:
                    zz.append(y['text'])
                    result.append(y)
        obj['children']= result
        for t in obj['children']:
            self.deldoublon(t)

    def listfileindir1(self, path_abs_current = None):
        if path_abs_current is  None or path_abs_current == "":
            if self.defaultdir is None:
                pathabs = os.getcwd()
            else:
                pathabs = self.defaultdir
        else:
            if self.rootfilesystem in path_abs_current:
                pathabs = os.path.abspath(path_abs_current)
            else:
                pathabs = self.rootfilesystem
        self.dirinfos = {
            "path_abs_current" : pathabs,
            "list_dirs_current" : os.walk(pathabs).next()[1],
            "list_files_current" : os.walk(pathabs).next()[2],
            "parentdir" : os.path.abspath(os.path.join(pathabs, os.pardir)),
            "rootfilesystem" : self.rootfilesystem,
            "defaultdir" : self.defaultdir
        }
        return self.dirinfos
