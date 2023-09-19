# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from lib import utils
import time

import os

plugin = {"VERSION": "2.2", "NAME": "enddeploy", "TYPE": "all"}  # fmt: skip

logger = logging.getLogger()

@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug(
        f'call {plugin} from {message["from"]} session id {sessionid}'
    )
    logging.getLogger().debug("###################################################")
    if objectxmpp.config.agenttype in ["relayserver"]:
        try:
            objectxmpp.mutexslotquickactioncount.acquire()
            # Convention 1 ban
            pathfile = utils._path_packagequickaction()
            filedeploy = [x for x in os.listdir(pathfile) if x.endswith("QDeploy")]
            logging.getLogger().debug(f"filedeploy {filedeploy}")
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
                        nbpool = res["result"] if res["code"] == 0 else "????"
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
                    f"""netstat -tpn | grep -v tcp6 | grep -v sshd | grep ssh | grep ESTABLISHED | grep '{datesession["ipmachine"]}'"""
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
                            f'Stopping file transfer {datesession["packagefile"]} [package {datesession["name"]}] to machine {datesession["jidmachine"].split("/")[1]}'
                        )
                        objectxmpp.xmpplog(
                            f'Stopping file transfer {datesession["packagefile"]} [package {datesession["name"]}] to machine {datesession["jidmachine"].split("/")[1]}',
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
                            utils.encode_strconsole(f"kill -6 {processus}")
                        )
                        if result1["code"] != 0:
                            logger.error(
                                f'the process {processus} closed with the status {str(result1["result"])}'
                            )
        # add session id pour clear interdiction apres un certain momment
        objectxmpp.banterminate[sessionid] = time.time()
    # add session id pour bloquage message
    objectxmpp.ban_deploy_sessionid_list.add(sessionid)
