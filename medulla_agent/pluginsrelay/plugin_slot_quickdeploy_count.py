#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import json
import logging
import traceback
import time
from lib import utils

logger = logging.getLogger()
plugin = {"VERSION": "2.0", "NAME": "slot_quickdeploy_count", "TYPE": "relayserver"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("#################################################")
    logger.debug(plugin)
    logger.debug(json.dumps(data, indent=4))
    logger.debug(
        "concurent deploy %s"
        % json.dumps(objectxmpp.concurrentquickdeployments, indent=4)
    )
    logger.debug("#################################################")
    strjidagent = str(objectxmpp.boundjid.bare)
    if "subaction" in data:
        if data["subaction"] == "restitution":
            try:
                ts = int(time.time())
                objectxmpp.mutex.acquire(1)
                try:
                    # concurrentquickdeployments list object i {
                    # numerodesession : timestamp }
                    try:
                        del objectxmpp.concurrentquickdeployments[sessionid]
                    except KeyError:
                        logger.debug("Session %s missing" % sessionid)
                    logger.debug("Deleting session id %s" % sessionid)
                    objectxmpp.xmpplog(
                        "Deployment message acknowledged\nFreeing quick deployment resource "
                        "%s\nResource status: %s/%s"
                        % (
                            sessionid,
                            len(objectxmpp.concurrentquickdeployments),
                            objectxmpp.config.nbconcurrentquickdeployments,
                        ),
                        type="deploy",
                        sessionname=sessionid,
                        priority=-1,
                        action="xmpplog",
                        who=strjidagent,
                        module="Deployment | Qdeploy | Notify",
                        date=None,
                        fromuser="",
                    )
                except KeyError:
                    logger.error("\n%s" % (traceback.format_exc()))
                    pass
                timeoutslot(objectxmpp)
            finally:
                objectxmpp.mutex.release()
            nbdeploy = len(objectxmpp.concurrentquickdeployments)
            pathfile = utils._path_packagequickaction()
            if nbdeploy == 0:
                time.sleep(3)
            replay(objectxmpp, sessionid)
        elif data["subaction"] == "deployfile":
            if (
                objectxmpp.mutex.locked()
                or objectxmpp.mutexslotquickactioncount.locked()
            ):
                return
            else:
                try:
                    objectxmpp.mutex.acquire(1)
                    timeoutslot(objectxmpp)
                finally:
                    objectxmpp.mutex.release()
                replay(objectxmpp, sessionid)


def replay(objectxmpp, sessionid):
    try:
        objectxmpp.mutexslotquickactioncount.acquire()
        nbdeploy = len(objectxmpp.concurrentquickdeployments)
        logger.debug(
            "Resource status: %s/%s"
            % (nbdeploy, objectxmpp.config.nbconcurrentquickdeployments)
        )
        # charge les fichiers terminant par QDeploy
        pathfile = utils._path_packagequickaction()
        filedeploy = [
            os.path.join(pathfile, x)
            for x in os.listdir(pathfile)
            if x.endswith("QDeploy")
        ]
        if (
            nbdeploy >= 0
            and nbdeploy < objectxmpp.config.nbconcurrentquickdeployments
            and len(filedeploy) > 0
        ):
            index = 0
            while (
                len(objectxmpp.concurrentquickdeployments)
                < objectxmpp.config.nbconcurrentquickdeployments
            ):
                # lancement des déploiements en fichier.
                try:
                    pathnamefile = filedeploy[index]
                    index += 1
                    namefile = os.path.basename(pathnamefile)
                    tabfile = namefile.split("@_@_@")
                    idmachine = tabfile[1]
                    sessioniddata = tabfile[0]
                    # load file into msgstruct
                    try:
                        with open(pathnamefile, "r") as file:
                            msgstruct = file.read()
                    except BaseException:
                        break
                    finally:
                        os.remove(pathnamefile)
                        res = utils.simplecommand(
                            "ls %s | wc -l"
                            % os.path.join(
                                utils._path_packagequickaction(), "*.QDeploy"
                            )
                        )
                        if res["code"] == 0:
                            nbpool = res["result"]
                        else:
                            nbpool = "????"
                        objectxmpp.xmpplog(
                            "Deleting deployment %s "
                            "from queue %s : %s"
                            % (sessionid, str(objectxmpp.boundjid.bare), nbpool),
                            type="deploy",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=str(objectxmpp.boundjid.bare),
                            module="Deployment | Qdeploy | Notify",
                            date=None,
                            fromuser="",
                        )
                    try:
                        objectxmpp.mutex.acquire(1)
                        # addition concurent quick deployement
                        logger.debug("Creating quick deployment %s" % (sessioniddata))
                        objectxmpp.concurrentquickdeployments[sessioniddata] = int(
                            time.time()
                        )
                    finally:
                        objectxmpp.mutex.release()
                    logger.debug("Sending deployment %s to machine" % (sessioniddata))
                    objectxmpp.send_message(
                        mto=idmachine, mbody=msgstruct, mtype="chat"
                    )
                except IndexError:
                    break
    finally:
        objectxmpp.mutexslotquickactioncount.release()


def timeoutslot(objectxmpp):
    ts = int(time.time())
    supp = []
    for slot in objectxmpp.concurrentquickdeployments:
        if int(ts - objectxmpp.concurrentquickdeployments[slot]) > 60:
            # rend le slot si time est supérieur a 60
            supp.append(slot)
            logger.debug("Session id %s exists since 60 seconds" % slot)
    # on libere les slots superieur a 60

    for delkey in supp:
        logger.debug("Freeing resource %s" % delkey)
        del objectxmpp.concurrentquickdeployments[delkey]
        objectxmpp.xmpplog(
            "Freeing quick deployment resource %s after timeout\n"
            "Resource status: %s/%s"
            % (
                delkey,
                len(objectxmpp.concurrentquickdeployments),
                objectxmpp.config.nbconcurrentquickdeployments,
            ),
            type="deploy",
            sessionname=delkey,
            priority=-1,
            action="xmpplog",
            who=str(objectxmpp.boundjid.bare),
            module="Deployment | Qdeploy | Notify",
            date=None,
            fromuser="",
        )
