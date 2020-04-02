# -*- coding: utf-8 -*-
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
import os


import logging
logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25


plugin={"VERSION": "1.0", "NAME" : "installpluginscheduled", "TYPE" : "all"}

def action( objetxmpp, action, sessionid, data, message, dataerreur ):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("########AGENT INSTALL PLUGINS SCHEDULED#############")
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s from %s"%(plugin,message['from']))
    logging.getLogger().debug("###################################################")
    if action == 'installpluginscheduled':
        if len(data) != 0 :
            namefile =  os.path.join(objetxmpp.config.pathpluginsscheduled, data['pluginname'])
            print namefile
            logging.getLogger().debug("###################################################")
            try:
                fileplugin = open(namefile, "w")
                fileplugin.write(str(data['datafile']))
                fileplugin.close()
            except :
                print "Error: cannor write on file"
                return
            #msg = "install plugin scheduled %s on %s"%(data['pluginname'],message['to'].user)
