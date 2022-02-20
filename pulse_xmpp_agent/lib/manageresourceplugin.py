# -*- coding: utf-8; -*-
#
# (c) 2016-2020 siveo, http://www.siveo.net
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
# file pulse_xmpp_agent/lib/manageresourceplugin.py
#

import logging
from lib.utils import getRandomName
import time

logger = logging.getLogger()


class errorresource(Exception):
    pass


class resource_plugin:
    """
    # running manage ressource
    self.manage_plugin = resource_plugin(self)

    eg: creation ressource this ressour calling function self.handleinventory
    if all taked resources are give back then call function
    ce parameter is argv (list argument) et pam (dict argument)


    self.manage_plugin.createresource( "updateresource",
                                         self. .handleinventory,
                                        typeaction="call_function",
                                        *[],
                                        **pam)
    ----------------------------------------------------
    In all plugin asynchrone running

    # take resource from plugin asynchrone execution
    jeton = self.manage_plugin.take_resource("updateresource")

    # proess plugin .......

    # give back ressource jeton
    self.manage_plugin.free_resource("updateresource", jeton)

    """

    def __init__(self, objectxmpp, schedule_time=60):
        self.resource = {}
        self.objectxmpp = objectxmpp
        self.objectxmpp.schedule(
            "manageresourceplugin", schedule_time, self.action_resource, repeat=True
        )
        logger.debug("Creation resource manager")

    def createresource(
        self,
        nameresource,
        nameplugin_or_handler,
        typeaction="call_plugin",
        *args,
        **kwargs
    ):
        logger.debug(
            "Creation resource name %s de type %s" % (nameresource, typeaction)
        )
        self.resource[nameresource] = {
            "plugin_name": nameplugin_or_handler,
            "typeaction": typeaction,
            "argv": args,
            "kwargs": kwargs,
            "countresource": -1,
            "creationtime": time.time(),
            "jetonlist": {},
        }

    def deleteresource(self, nameresource):
        logger.debug("Delete resource name %s" % (nameresource))
        del self.resource[nameresource]

    def take_resource(self, nameresource, timeout=100):

        if nameresource in self.resource:
            jeton = getRandomName(10, "resourcejeton")
            t = time.time() + timeout
            logger.debug(
                "take resource %s jeton %s timemax %s ressource"
                % (nameresource, jeton, timeout)
            )
            if self.resource[nameresource]["countresource"] == -1:
                self.resource[nameresource]["countresource"] = 1
            else:
                self.resource[nameresource]["countresource"] += 1

            self.resource[nameresource]["jetonlist"][jeton] = t
            logger.debug(
                "resource activate %s" % (self.resource[nameresource]["countresource"])
            )
            return jeton
        else:
            # error pas de resource existe.
            logger.error("imposible take resouce name %s" % (nameresource))
        return -1

    def free_resource(self, nameresource, jeton):
        """
        give back resource
        """
        if nameresource in self.resource:
            if jeton in self.resource[nameresource]["jetonlist"]:
                logger.debug("give back resource %s jeton %s" % (nameresource, jeton))
                del self.resource[nameresource]["jetonlist"][jeton]
                self.resource[nameresource]["countresource"] -= 1

    def action_resource(self):
        self.check_resource()
        for nameresource in self.resource:
            if self.resource[nameresource]["countresource"] == 0:
                # recuperation du typeaction
                if self.resource[nameresource]["typeaction"] == "call_function":
                    self.resource[nameresource]["plugin_name"](
                        self.resource[nameresource]["argv"],
                        self.resource[nameresource]["kwargs"],
                    )
                    # la resource doit etre supprimer
                    self.resource[nameresource]
                elif self.resource[nameresource]["typeaction"] == "call_plugin":
                    datasend = {
                        "action": self.resource[nameresource]["plugin_name"],
                        "sessionid": getRandomName(10, "resourcejeton"),
                        "data": self.resource[nameresource]["kwargs"],
                    }
                    msg = {
                        "to": self.objectxmpp.boundjid.bare,
                        "from": self.objectxmpp.boundjid.bare,
                    }

                    self.objectxmpp.call_plugin(
                        datasend["action"],
                        self.objectxmpp,
                        datasend["action"],
                        datasend["sessionid"],
                        datasend["data"],
                        msg,
                        {},
                    )

    def check_resource(self):
        # parcoure les resources et regarde si des timeouts sont arrivés
        temp = time.time()
        for nameresource in self.resource:
            for jeton in self.resource[nameresource]["jetonlist"]:
                if temp > self.resource[nameresource]["jetonlist"][jeton]:
                    del self.resource[nameresource]["jetonlist"][jeton]
                    self.resource[nameresource]["countresource"] -= 1
