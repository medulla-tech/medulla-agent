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
# file : pulse_agent_plugins/relay/plugin_cluster.py

import json
import logging

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25

plugin = {"VERSION": "1.14", "NAME": "cluster", "VERSIONAGENT": "2.0.0", "TYPE": "relayserver", "DESC": "update list ARS cluster",} # fmt: skip


def refreshremotears(objectxmpp, action, sessionid):
    for ars in objectxmpp.jidclusterlistrelayservers:
        result = {
            "action": "%s" % action,
            "sessionid": sessionid,
            "data": {
                "subaction": "refreshload",
                "data": {
                    "chargenumber": objectxmpp.checklevelcharge()
                    + objectxmpp.managefifo.getcount()
                },
            },
            "ret": 0,
            "base64": False,
        }
        objectxmpp.send_message(mto=ars, mbody=json.dumps(result), mtype="chat")
    logger.debug(
        "plugin cluster : refresh charge (%s) of ars %s to list remote ars cluster %s"
        % (
            objectxmpp.checklevelcharge() + objectxmpp.managefifo.getcount(),
            objectxmpp.boundjid.bare,
            objectxmpp.jidclusterlistrelayservers,
        )
    )


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s session id %s" % (plugin, message["from"], sessionid))
    logger.debug("###################################################")
    logger.debug(json.dumps(data, indent=4))
    if "subaction" in data:
        if data["subaction"] == "startmmc":
            objectxmpp.levelcharge["charge"] = 0
            objectxmpp.levelcharge["machinelist"] = []
            logger.debug("start mmc clear charge ARS")
        elif data["subaction"] == "initclusterlist":
            # update list cluster jid
            # list friend ars
            jidclusterlistrelayservers = [
                jidrelayserver
                for jidrelayserver in data["data"]
                if jidrelayserver != message["to"]
            ]

            # We delete the references to the ARS if it is not in
            # jidclusterlistrelayservers
            for ars in jidclusterlistrelayservers:
                if ars not in objectxmpp.jidclusterlistrelayservers:
                    objectxmpp.jidclusterlistrelayservers[ars] = {"chargenumber": 0}

            delars = []
            for ars in objectxmpp.jidclusterlistrelayservers:
                if ars not in jidclusterlistrelayservers:
                    delars.append(ars)

            for ars in delars:
                del objectxmpp.jidclusterlistrelayservers[ars]

            for ars in objectxmpp.jidclusterlistrelayservers:
                result = {
                    "action": "%s" % action,
                    "sessionid": sessionid,
                    "data": {
                        "subaction": "refreshload",
                        "data": {
                            "chargenumber": objectxmpp.checklevelcharge()
                            + objectxmpp.managefifo.getcount()
                        },
                    },
                    "ret": 0,
                    "base64": False,
                }
                print(ars)
                print(result)
                objectxmpp.send_message(mto=ars, mbody=json.dumps(result), mtype="chat")
            logger.debug(
                "new ARS list friend of cluster : %s"
                % objectxmpp.jidclusterlistrelayservers
            )
        elif data["subaction"] == "refreshload":
            objectxmpp.jidclusterlistrelayservers[message["from"]] = data["data"]
            logger.debug(
                "new ARS list friend of cluster : %s"
                % objectxmpp.jidclusterlistrelayservers
            )
        elif data["subaction"] == "removeresource":
            if "machinejid" in data["data"]:
                objectxmpp.delmachineinlevelmachinelist(data["data"]["machinejid"])
            else:
                objectxmpp.delmachineinlevelmachinelist(message["from"])
            logger.debug(
                "levelcharge %s %s"
                % (
                    objectxmpp.boundjid.bare,
                    json.dumps(objectxmpp.levelcharge, indent=4),
                )
            )
            refreshremotears(objectxmpp, action, sessionid)
            if "user" in data["data"]:
                user = data["data"]["user"]
            else:
                user = "master"
            objectxmpp.xmpplog(
                "Cluster plugin : ARS (%s) load : %s"
                % (
                    objectxmpp.boundjid.bare,
                    objectxmpp.checklevelcharge() + objectxmpp.managefifo.getcount(),
                ),
                type="deploy",
                sessionname=sessionid,
                priority=-1,
                action="xmpplog",
                who=objectxmpp.boundjid.bare,
                how="",
                why="",
                module="Deployment | Cluster | Notify",
                date=None,
                fromuser=user,
                touser="",
            )
        elif data["subaction"] == "takeresource":
            if "machinejid" in data["data"]:
                objectxmpp.addmachineinlevelmachinelist(data["data"]["machinejid"])
            else:
                objectxmpp.addmachineinlevelmachinelist(message["from"])
            logger.debug(
                "levelcharge %s %s"
                % (
                    objectxmpp.boundjid.bare,
                    json.dumps(objectxmpp.levelcharge, indent=4),
                )
            )
            refreshremotears(objectxmpp, action, sessionid)
            if "user" in data["data"]:
                user = data["data"]["user"]
            else:
                user = "master"
            objectxmpp.xmpplog(
                "Cluster plugin : ARS (%s) load : %s"
                % (
                    objectxmpp.boundjid.bare,
                    objectxmpp.checklevelcharge() + objectxmpp.managefifo.getcount(),
                ),
                type="deploy",
                sessionname=sessionid,
                priority=-1,
                action="xmpplog",
                who=objectxmpp.boundjid.bare,
                how="",
                why="",
                module="Deployment | Cluster | Notify",
                date=None,
                fromuser=user,
                touser="",
            )
