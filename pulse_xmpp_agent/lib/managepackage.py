#!/usr/bin/env python
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

import sys,os,platform
import os.path
import json
 

class managepackage:
    #JFK
    @staticmethod
    def packagedir():
        if sys.platform.startswith('linux'):
            return os.path.join("/", "var" ,"lib","pulse2","packages")
        elif sys.platform.startswith('win'):
            return os.path.join(os.environ["ProgramFiles"], "Pulse", "packages")
        elif sys.platform.startswith('darwin'):
            return os.path.join("/", "Library", "Application Support", "Pulse", "packages")
        else:
            return None

    @staticmethod
    def listpackages():
        return [ os.path.join(managepackage.packagedir(),x) for x in os.listdir(managepackage.packagedir()) if os.path.isdir(os.path.join(managepackage.packagedir(),x)) ]

    @staticmethod
    def loadjsonfile(filename):
        if os.path.isfile(filename ):
            with open(filename,'r') as info:
                dd = info.read()
            try:
                jr= json.loads(dd.decode('utf-8', 'ignore'))
                return jr
            except:
                print "erreur decodage"
                pass
        return None
    
    @staticmethod
    def getdescriptorpackagename(packagename):
        for t in managepackage.listpackages():
            jr = managepackage.loadjsonfile(os.path.join(t,"xmppdeploy.json"))
            if 'info' in jr \
                and ('software' in jr['info'] and 'version'  in jr['info']) \
                and (jr['info']['software'] == packagename or jr['info']['name'] == packagename):
                return jr
        return None

    @staticmethod
    def getversionpackagename(packagename):
        for t in managepackage.listpackages():
            jr = managepackage.loadjsonfile(os.path.join(t,"xmppdeploy.json"))
            if 'info' in jr \
                and ('software' in jr['info'] and 'version'  in jr['info']) \
                and (jr['info']['software'] == packagename or jr['info']['name'] == packagename):
                return jr['info']['version']
        return None

    @staticmethod
    def getpathpackagename(packagename):
        for t in managepackage.listpackages():
            jr = managepackage.loadjsonfile(os.path.join(t,"xmppdeploy.json"))
            if 'info' in jr \
                and (('software' in jr['info'] and jr['info']['software'] == packagename )\
                or ( 'name'  in jr['info'] and  jr['info']['name'] == packagename)):
                return t
        return None

        
