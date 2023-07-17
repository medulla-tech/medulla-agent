# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
from lib import utils
import time

import os

plugin = {"VERSION": "2.1", "NAME": "enddeploy", "TYPE": "all"}  # fmt: skip

logger = logging.getLogger()


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug(
        "call %s from %s session id %s" % (plugin, message["from"], sessionid)
    )
    logging.getLogger().debug("###################################################")
    if objectxmpp.config.agenttype in ["relayserver"]:
        try:
            objectxmpp.mutexslotquickactioncount.acquire()
            # Convention 1 ban
            pathfile = utils._path_packagequickaction()
            filedeploy = [x for x in os.listdir(pathfile) if x.endswith("QDeploy")]
            logging.getLogger().debug("filedeploy %s" % filedeploy)
            # Remove all pool files
            for filledeployement in filedeploy:
                tabfile = filledeployement.split("@_@_@")
                idmachine = tabfile[1]
                sessionfile = tabfile[0]
                # Charge fichier dans  msgstruct
                try:
                    if sessionid == sessionfile:
                        os.remove(os.path.join(pathfile, filledeployement))
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
                            "<span class='log_err'>ABORT DEPLOYMENT CANCELLED BY USER</span>\n "
                            "Deleting deployment %s from queue %s : %s"
                            % (sessionid, str(objectxmpp.boundjid.bare), nbpool),
                            type="deploy",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=str(objectxmpp.boundjid.bare),
                            module="Deployment | Qdeploy | Notify",
                            date=None,
                            fromuser=data["login"],
                        )
                        break
                except BaseException:
                    pass
        finally:
            objectxmpp.mutexslotquickactioncount.release()

        if objectxmpp.session.isexist(sessionid):
            datesession = objectxmpp.session.sessionfromsessiondata(
                sessionid
            ).getdatasession()
            result = utils.simplecommand(
                utils.encode_strconsole(
                    "netstat -tpn | grep -v tcp6 | grep -v sshd | grep ssh | grep ESTABLISHED | grep '%s'"
                    % datesession["ipmachine"]
                )
            )
            if result["code"] == 0:
                # termine ssh connection to AM
                for connection_ssh in result["result"]:
                    parameterconnection = [
                        x for x in connection_ssh.split(" ") if x != ""
                    ]
                    if "ssh" in parameterconnection[6]:
                        processus = parameterconnection[6].split("/")[0]
                        logger.debug(
                            "Stopping file transfer %s [package %s] to machine %s"
                            % (
                                datesession["packagefile"],
                                datesession["name"],
                                datesession["jidmachine"].split("/")[1],
                            )
                        )
                        objectxmpp.xmpplog(
                            "Stopping file transfer %s [package %s] to machine %s"
                            % (
                                datesession["packagefile"],
                                datesession["name"],
                                datesession["jidmachine"].split("/")[1],
                            ),
                            type="deploy",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=objectxmpp.boundjid.bare,
                            how="",
                            why="",
                            module="Deployment | Transfer | Notify",
                            date=None,
                            fromuser=datesession["login"],
                            touser="",
                        )
                        result1 = utils.simplecommand(
                            utils.encode_strconsole("kill -6 %s" % processus)
                        )
                        if result1["code"] != 0:
                            logger.error(
                                "the process %s closed with the status %s"
                                % (processus, str(result1["result"]))
                            )
        # add session id pour clear interdiction apres un certain momment
        objectxmpp.banterminate[sessionid] = time.time()
    # add session id pour bloquage message
    objectxmpp.ban_deploy_sessionid_list.add(sessionid)
