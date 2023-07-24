# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

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
        **kwargs,
    ):
        logger.debug(f"Creation resource name {nameresource} de type {typeaction}")
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
        logger.debug(f"Delete resource name {nameresource}")
        del self.resource[nameresource]

    def take_resource(self, nameresource, timeout=100):
        if nameresource in self.resource:
            jeton = getRandomName(10, "resourcejeton")
            t = time.time() + timeout
            logger.debug(
                f"take resource {nameresource} jeton {jeton} timemax {timeout} ressource"
            )
            if self.resource[nameresource]["countresource"] == -1:
                self.resource[nameresource]["countresource"] = 1
            else:
                self.resource[nameresource]["countresource"] += 1

            self.resource[nameresource]["jetonlist"][jeton] = t
            logger.debug(
                f'resource activate {self.resource[nameresource]["countresource"]}'
            )
            return jeton
        else:
            # error pas de resource existe.
            logger.error(f"imposible take resouce name {nameresource}")
        return -1

    def free_resource(self, nameresource, jeton):
        """
        give back resource
        """
        if nameresource in self.resource:
            if jeton in self.resource[nameresource]["jetonlist"]:
                logger.debug(f"give back resource {nameresource} jeton {jeton}")
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
