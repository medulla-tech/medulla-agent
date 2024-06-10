#!/usr/bin/python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


import logging
import json

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "plugin_askinfo", "TYPE": "submaster"}  # fmt: skip


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("#################################################")
    logger.debug(plugin)
    logger.debug(json.dumps(data, indent=4))
    logger.debug("#################################################")

    if not data:
        return
    if "fromplugin" in data:
        # If item exists, redirects to the plugin named by the action
        data["action"] = data["fromplugin"]
        logger.debug("Response action is calling the plugin %s" % data["action"])
        logger.debug(json.dumps(data, indent=4))
    else:
        logger.warn(
            "The item 'fromplugin' doesn't exist, action reponse calls the plugin %s"
            % data["action"]
        )
        logger.debug(json.dumps(data, indent=4))
    if not "typeinfo" in data:
        logger.error(
            "The item 'typeinfo' doesn't exists into the message comming from %s plugin %s"
            % (message["from"].bare, data["action"])
        )
        logger.error("######\n%s\n#####" % (json.dumps(data, indent=4)))
    if data["typeinfo"] == "info_xmppmachinebyuuid":
        if not "host" in data:
            logger.error("The host is missing for info_xmppmachinebyuuid")
            return True
        data["host"] = data["host"].upper()
        data["host"] = data["host"].replace("UUID", "")
        try:
            integerid = int(data["host"])
        except ValueError:
            logger.error("The inventory uuid is missing for info_xmppmachinebyuuid")
            return True

        # #####WORKING info_xmppmachinebyuuid######
        func = getattr(xmppobject, "info_xmppmachinebyuuid")
        result = func(str(integerid))
        data["infos"] = result

        if "sendother" in data and data["sendother"] != "":
            searchjid = data["sendother"].split("@")
            jidmachine = dict(data)
            datasend = {
                "action": data["fromplugin"],
                "sessionid": sessionid,
                "data": data,
                "base64": False,
            }
            for key in searchjid[1:]:
                try:
                    jidmachine = jidmachine[key]
                except KeyError:
                    logger.error(
                        "jid point item sendother in data false.\n"
                        "Path in the dictionary described by the keys does not exist.\n"
                        " example {....sendother : \"autre@infos\"} jid is databpointer by data['autre']['infos']\n"
                        " data is %s" % (json.dumps(data, indent=4))
                    )
                    break
            jidmachine = str(jidmachine)
            if jidmachine != "":
                logger.debug("Sending data to machine %s" % jidmachine)
                logger.debug(json.dumps(datasend, indent=4))
                xmppobject.send_message(
                    mto=jidmachine, mbody=json.dumps(datasend), mtype="chat"
                )
        if not "sendemettor" in data:
            data["sendemettor"] = True
        if data["sendemettor"] == True:
            logger.debug("Sending data to emittor %s" % jidmachine)
            logger.debug(json.dumps(datasend, indent=4))
            xmppobject.send_message(
                mto=message["from"], mbody=json.dumps(datasend), mtype="chat"
            )
    # ########################ASK INFORMATION other#############################
    # elsif information type other
    return True
