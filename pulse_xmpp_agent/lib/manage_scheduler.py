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
# file manage_scheduler.py

import sys,os
import os.path
#import traceback
import logging
import time
from datetime import datetime
import croniter
import json
from random import randint


#from lib.utils import

logger = logging.getLogger()

class manage_scheduler:
    """
    This class manages events and it executes the scheduler plugins that are contained in
     The / descriptor_scheduler_relay or descriptor_scheduler_machine
     Scheduled plugins are files prefixed by scheduling_

     These files must have a function schedule_main
     Def schedule_main (objectxmpp):
         Contained function

     These files also need to have a dict with its crontab descriptor.
     # Nb -1 infinite
     SCHEDULE = {"schedule": "* / 1 * * * *", "nb": -1}
     Nb makes it possible to limit the operation a n times.
    """
    def __init__(self, objectxmpp):
        #creation repertoire si non exist.
        try:
            objectxmpp.config.listcrontabforpluginscheduled = objectxmpp.config.listcrontabforpluginscheduled.replace(os.linesep,"").replace("'",'"').strip('"')
            try :
                objcromtabconf = json.loads(objectxmpp.config.listcrontabforpluginscheduled)
            except Exception as e:
                logging.getLogger().error("Error json parameters listcrontabforpluginscheduled file manage_scheduler.ini")
                logging.getLogger().error(str(e))
        except AttributeError as e:
            logging.getLogger().warning("If you use the configuration to schedule some plugins,"\
                    "do not forget to add conf in manage_scheduler.ini for these plugins."\
                    "json parameters listcrontabforpluginscheduled."\
                    "and declare the configuration of the scheduler in agentconf.ini"\
                    "[Plugin]"\
                    "pluginlist = manage_scheduler")
            objcromtabconf = {}
            logging.getLogger().warning(str(e))

        self.taches = []

        self.now = datetime.now()

        self.objectxmpp = objectxmpp

        #addition path to sys
        if  self.objectxmpp.config.agenttype in ['relayserver']:
            descriptor_scheduler = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "descriptor_scheduler_relay")
        elif self.objectxmpp.config.agenttype in ['machine']:
            descriptor_scheduler = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "descriptor_scheduler_machine")
        self.directoryschedule =  os.path.abspath(descriptor_scheduler)
        #print "directory to descriptor scheduler (%s : %s)"%(self.objectxmpp.config.agenttype, self.directoryschedule )
        sys.path.append(self.directoryschedule)

        #creation repertoire si non exist
        if not os.path.exists(self.directoryschedule):
            logging.getLogger().debug("create directory scheduler %s"%self.directoryschedule)
            os.makedirs(self.directoryschedule, 0700 )
        namefile = os.path.join(self.directoryschedule,"__init__.py")
        if not os.path.exists(namefile):
            fichier = open(namefile, "w")
            fichier.write("###WARNING : never delete this file")
            fichier.close()

        for x in os.listdir(self.directoryschedule):
            if x.endswith(".pyc") or not x.startswith("scheduling"):
                continue
            #recupere SCHEDULERDATA
            name = x[11:-3]
            try:
                datascheduler = self.litschedule(name)
                datascheduler['nameplugin'] = name
                datascheduler['schedule'] = self.replacecrontabdescriptor(datascheduler['schedule'])
                for i in objcromtabconf:
                    if i['nameplugin'] == name :
                        i['schedule'] = self.replacecrontabdescriptor(i['schedule'])
                        datascheduler = i
                        if 'persistence' in datascheduler and datascheduler['persistence']:
                            #recupere crontab si existe.
                            namefilecrontabpresistence = os.path.join(self.directoryschedule, "%s.crontab"%i['nameplugin'])
                            if not os.path.exists(namefilecrontabpresistence):
                                fichier = open(namefilecrontabpresistence, "w")
                                fichier.write(i['schedule'])
                                fichier.close()
                            else:
                                fichier = open(namefilecrontabpresistence, "r")
                                datascheduler['schedule'] = fichier.read()
                                fichier.close()
                logging.getLogger().debug("load format crontab : %s for plugin scheduled %s"%(datascheduler['schedule'], datascheduler['nameplugin'] ))
                self.add_event(name, datascheduler)
            except Exception as e:
                logging.getLogger().error(str(e))
                pass

    def replacecrontabdescriptor(self, descrip):
        rep =[]
        start = [pos for pos, char in enumerate(descrip) if char == "$"]
        end   = [pos+1 for pos, char in enumerate(descrip) if char == "]"]
        if len(start) == len(end):
            # the descriptors
            mergeinfolist = list(zip(start, end))
            for (x,y) in mergeinfolist:
                replacedata = {}
                #print descrip[int(x+2):int(y-1)]
                l = descrip[int(x+2):int(y-1)].split(',')
                if len(l) == 2 and int(l[0]) < int(l[1]):
                    searchvalue =  randint(int(l[0]), int(l[1]))
                    replacedata = { 
                                'descriptor' : descrip[int(x):int(y)],
                                'value' : searchvalue }
                    rep.append(replacedata)
                else:
                    return ''
        for t in rep:
            descrip = descrip.replace(t['descriptor'], str(t['value']), 1)
        return descrip

    def add_event(self, name, datascheduler):
        tabcron = datascheduler['schedule']
        cron = croniter.croniter(tabcron, self.now)
        nextd = cron.get_next(datetime)
        if 'nb' in datascheduler:
            nbcount = datascheduler['nb']
        else:
            nbcount = -1
        obj=  {"name": name, "exectime" : time.mktime(nextd.timetuple()) , "tabcron" : tabcron , "timestart" : str(self.now), "nbcount" : nbcount, "count" : 0 }
        self.taches.append(obj)

    def process_on_event(self):
        now = datetime.now()
        secondeunix = time.mktime(now.timetuple())
        deleted=[]
        for t in self.taches:
            if (secondeunix - t["exectime"])  > 0:
                #replace exectime
                t["count"] = t["count"] + 1
                if "nbcount" in t and t["nbcount"] != -1 and  t["count"] > t["nbcount"]:
                    deleted.append(t)
                    logging.getLogger().debug("terminate plugin %s"%t)
                    continue
                cron = croniter.croniter(t["tabcron"], now)
                nextd = cron.get_next(datetime)
                t["exectime"] = time.mktime(nextd.timetuple())
                self.call_scheduling_main(t["name"], self.objectxmpp)
        for y in deleted:
            self.taches.remove(y)

    def call_scheduling_main(self, name, *args, **kwargs):
        mod = __import__("scheduling_%s"%name)
        logging.getLogger().debug("exec plugin scheduling_%s"%name)
        mod.schedule_main(*args, **kwargs)

    def call_scheduling_mainspe(self, name, *args, **kwargs):
        mod = __import__("scheduling_%s"%name)

        return mod.schedule_main

    def litschedule(self, name):
        mod = __import__("scheduling_%s"%name)
        return mod.SCHEDULE
