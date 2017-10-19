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
"""
This plugin loads all deploy scheduler, and sends an execution request to a master
"""
import json

plugin = {"VERSION" : "1.0", "NAME" : "scheduling_deploy",  "TYPE" : "scheduled"}

# nb  -1 infinie
# all 2 minutes

SCHEDULE = {"schedule" : "*/2 * * * *", "nb" : -1}
#SCHEDULE = { "schedule" : "30 22 * * 2", "nb" : -1 }
def schedule_main(objectxmpp):
    objectxmpp.Deploybasesched.openbase()
    for k, v in objectxmpp.Deploybasesched.dbsessionscheduler.iteritems():
        obj = json.loads(v)
        obj['data']['fromaction'] = obj['action']
        obj['action'] = "machineexecutionscheduler"
        del obj['data']['descriptor']
        del obj['data']['packagefile']
        # send message to master in plugin_machineexecutionscheduler
        objectxmpp.send_message(mto = obj['data']['jidmaster'],
                                    mbody = json.dumps(obj),
                                    mtype = 'chat')
    objectxmpp.Deploybasesched.closebase()
