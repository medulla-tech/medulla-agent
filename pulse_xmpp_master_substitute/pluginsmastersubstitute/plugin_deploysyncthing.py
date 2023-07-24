#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from lib.plugins.xmpp import XmppMasterDatabase
from lib.utils import name_randomplus
from slixmpp import jid
import logging
import random

logger = logging.getLogger()
plugin = {"VERSION": "1.11", "NAME": "deploysyncthing", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, message, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    if "subaction" in data:
        # this action is calling for machine after terminate transfert
        # syncthing
        if "counttransfertterminate" in data["subaction"]:
            # on ajoute 1 au compteur syncthing dans le groupe.
            XmppMasterDatabase().incr_count_transfert_terminate(data["iddeploybase"])
            XmppMasterDatabase().update_transfert_progress(
                100, data["iddeploybase"], message["from"]
            )
        elif "completion" in data["subaction"]:
            # on update le niveau de progressions de transfert
            XmppMasterDatabase().update_transfert_progress(
                data["completion"], data["iddeploybase"], message["from"]
            )
        elif "initialisation" in data["subaction"]:
            # logger.debug("=====================================================")
            # le plugin a pour mission de deployer les partage sur les ARS du cluster.
            # puis propager les partages vers les machines. les machines en fonction de leur ARS attribués.
            # pour les partages entre ARS, il faut choisir 1 ARS comme le patron.
            # on appelle cette tache l election syncthing.
            # On choisie au hazard 1 ars static, dans la liste des ars du cluster.
            # la function getCluster_deploy_syncthing renvoit les ARS du cluster
            # la fonction getRelayServerfromjid renvoit les toutes les informations de ars
            # logger.debug("=====================================================")
            listclusterobjet = XmppMasterDatabase().getCluster_deploy_syncthing(
                data["iddeploy"]
            )

            deploy_syncthing_information = {}
            deploy_syncthing_information["namedeploy"] = listclusterobjet[0][0]
            deploy_syncthing_information["namecluster"] = listclusterobjet[0][2]
            deploy_syncthing_information["repertoiredeploy"] = listclusterobjet[0][1]

            clustersdata = json.loads(listclusterobjet[0][6])
            logging.getLogger().debug(json.dumps(clustersdata, indent=4))

            clu = {}
            clu["arslist"] = {}
            clu["arsip"] = {}
            clu["numcluster"] = clustersdata["numcluster"]
            nb = random.randint(0, clu["numcluster"] - 1)
            for (
                index,
                value,
            ) in enumerate(clustersdata["listarscluster"]):
                val = "%s" % jid.JID(value).bare
                if index == nb:
                    clu["elected"] = val
                clu["arslist"][val] = clustersdata["keysyncthing"][index]
                infoars = XmppMasterDatabase().getRelayServerfromjid(val)
                keycheck = ["syncthing_port", "ipserver", "ipconnection"]
                if [x for x in keycheck if x in infoars] == keycheck:
                    adressipserver = "tcp://%s:%s" % (
                        infoars["ipserver"],
                        infoars["syncthing_port"],
                    )
                    adressconnection = "tcp://%s:%s" % (
                        infoars["ipconnection"],
                        infoars["syncthing_port"],
                    )
                    clu["arsip"][val] = [
                        str(adressipserver),
                        str(adressconnection),
                        str("dynamic"),
                    ]
                else:
                    logging.getLogger().error("verify syncthing info for ars %s" % val)
                    clu["arsip"][val] = ["dynamic"]
            clu["namecluster"] = clustersdata["namecluster"]
            deploy_syncthing_information["agentdeploy"] = str(xmppobject.boundjid.bare)
            deploy_syncthing_information["cluster"] = clu
            deploy_syncthing_information["packagedeploy"] = listclusterobjet[0][2]
            deploy_syncthing_information["grp"] = listclusterobjet[0][7]
            deploy_syncthing_information["cmd"] = listclusterobjet[0][8]
            deploy_syncthing_information["syncthing_deploy_group"] = data["iddeploy"]

            # List of the machines for this share

            updatedata = []
            machines = XmppMasterDatabase().getMachine_deploy_Syncthing(
                data["iddeploy"], ars=None, status=2
            )

            partagemachine = []
            for machine in machines:
                partagemachine.append(
                    {
                        "mach": "%s" % jid.JID(machine[2]).bare,
                        "ses": machine[0],
                        "devi": machine[3],
                    }
                )
                updatedata.append(machine[5])

            deploy_syncthing_information["machines"] = partagemachine
            XmppMasterDatabase().updateMachine_deploy_Syncthing(
                updatedata, statusold=2, statusnew=3
            )

            datasend = {
                "action": "deploysyncthing",
                "sessionid": name_randomplus(30, "syncthingclusterinit"),
                "ret": 0,
                "base64": False,
                "data": {"subaction": "syncthingdeploycluster"},
            }
            datasend["data"]["objpartage"] = deploy_syncthing_information

            for ars in deploy_syncthing_information["cluster"]["arslist"]:
                datasend["data"]["ARS"] = ars
                xmppobject.send_message(
                    mto=ars, mbody=json.dumps(datasend), mtype="chat"
                )
