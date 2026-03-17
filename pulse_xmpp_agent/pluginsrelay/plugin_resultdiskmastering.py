# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import json
import os
import base64
import zlib
import time

from mmc.plugins.xmppmaster.master.lib.utils import simplecommand

plugin = {"VERSION": "0.1", "NAME": "resultdiskmastering", "TYPE": "relayserver"}  # fmt: skip

logger = logging.getLogger()


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s session id %s" % (plugin, message["from"], sessionid))
    logger.debug("###################################################")

    if "subaction" in data:
        if data["subaction"] == "log":
            # TODO: save logs associated to the data["action_id"] + data["uuid"]
            pass

        if data["subaction"] == "ping":
            """Recv
            - action    : resultdiskmastering / ping
            - desc      : Receive a ping message from davos client. The message contains some info from the client . It's the equivalent to registration on agents.
            - data:
                - uuid      : the machine UUID
                - mac       : the machine mac address
                - manifest  : the list of plugins and their version launched on davos
            - resp
                - to        : davos client
                - action    : resultping/pong
                - manifest  : list of plugins to update on davos client
            """
            uuid = data["uuid"]
            mac = data["mac"]
            server = data["server"]

            # Get the manifest for the canonic list of plugins

            davos_manifest = {}
            if "manifest" in data:
                davos_manifest = data["manifest"]

            manifest = get_plugins_manifest(objectxmpp, davos_manifest)

            datasend = {
                "from":objectxmpp.boundjid.bare,
                "sessionid": sessionid,
                "ret": 0,
                "base64": False,
                "agenttype": objectxmpp.config.agenttype,
                "action": "resultping" ,
                "data": {
                    "subaction":"pong",
                    "manifest": manifest
                }
            }

            # Get the substitut diskmastering jid
            substitute_diskmastering_jid = ""
            result = simplecommand("ejabberdctl connected_users")
            if result["code"] == 0:
                for e in result["result"]:
                    e = e.decode("utf-8")
                    if e.startswith("master_dma"):
                        substitute_diskmastering_jid = e.split("/")[0]
                        break

            datasend["data"]["substitute_jid"] = substitute_diskmastering_jid
            objectxmpp.send_message(mto=message["from"], mbody=json.dumps(datasend, indent=4), mtype="chat")

        if data["subaction"] == "askworkflow":
            """Recv
            - action    : resultdiskmastering / askworkflow
            - desc      : The machine has updated its plugins and is ready to work. In this state, the machine is asking what to do.
            - data:
                - uuid          : the machine UUID
                - mac           : the machine mac address
                - action_id     : the id of the action associated to the machine, found when booting
                - client_jid    : the davos client jid to return the workflow
            - resp
                - to            : master_dma@pulse
                - action        : diskmastering / askworkflow
                - manifest      : list of plugins to update on davos client
                - client_jid    : the davos client jid to return the workflow
                - action_id     : the action id found when booting
                - server        : relay (here). Equivalent to from
            """
            uuid = data["uuid"]
            mac = data["mac"]
            # Transfer the data to the master_img
            ask_workflow(objectxmpp, sessionid, message["from"].bare, uuid, mac, data["action_id"])

        if data["subaction"] == "register":
            datasend = {
                "action":"resultinventory",
                "from": objectxmpp.boundjid.bare,
                "to": "master_inv@pulse",
                "sessionid": sessionid,
                "ret": 0,
                "base64":False,
                "data":{
                    "inventory": data["inventory"],
                }
            }
            # Send inventory to master_inv@pulse
            objectxmpp.send_message(mto="master_inv@pulse", mbody=json.dumps(datasend, indent=4), mtype="chat")
            time.sleep(5)

        # TODO: what to do on <step execution done> event


def ask_workflow(objectxmpp, sessionid, client_jid, uuid, mac, action_id):
    """Send a workflow request to the substitute diskmastering.

    Args:
        objectxmpp (ClientXMPP): Instance of ClientXMPP Object.
        sessionid (str): The current sessionid. Keep the same sessionid through the whole process (for one machine).
        client_jid (str): The davos client jid, to know where the substitute diskmastering has to send the workflow.
        uuid (str): davos client UUID. Usefull to identify the machine.
        mac (str): Extra info, can be usefull to have it.
        action_id (int): The id of the action to execute on the machine. It's a reference to the whole workflow to execute."""
    datasend = {
        "from":objectxmpp.boundjid.bare,
        "to":"master_dma@pulse",
        "sessionid": sessionid,
        "ret": 0,
        "action": "diskmastering",
        "agenttype": objectxmpp.config.agenttype,
        "data":{
            "client_jid": client_jid,
            "subaction":"askworkflow",
            "sessionid":sessionid,
            "action_id":action_id,
            "uuid": uuid,
            "mac": mac,
        },
        "base64": False,
    }

    objectxmpp.send_message(mto="master_dma@pulse", mbody=json.dumps(datasend, indent=4), mtype="chat")


def get_plugins_manifest(objectxmpp, davos_manifest):
    """Generate a list of plugins to update on davos client.

    Args:
        objectxmpp (ClientXMPP) : Instance of ClientXMPP Object.
        davos_manifest (dict) : Davos client plugins list. Has the shape:
            {
            "plugin_aaa": "0.1",
            "plugin_bbb": "0.1"
            }

    Returns:
        dict: the list of plugins which have to be updated on davos client. It has the shape:
            {
                "plugin_aaa": {
                    "VERSION":"0.1",
                    "NAME":"aaa",
                    "TYPE":"davos",
                    "content": compressed and encoded plugin_content
                }
            }"""
    # The davos plugins are located in /var/lib/pulse2/imaging/davos/plugins, see /etc/pulse_xmpp_agent/diskmastering.ini, diskmastering_path to get it
    base_path=""
    plugins_path = ""

    if hasattr(objectxmpp.config, "diskmastering_path_plugin_base"):
        plugins_path = objectxmpp.config.diskmastering_path_plugin_base
    elif hasattr(objectxmpp.config, "diskmastering_path"):
        base_path = objectxmpp.config.diskmastering_path

    if plugins_path == "" and base_path == "":
        logger.warning("%s or %s empty"%(plugins_path, base_path))
        return {}

    # Generate the plugins path from base path if plugins path is empty
    if plugins_path == "":
        plugins_path = os.path.join(base_path, "davos", "xmpp_plugins")

    # Test if the plugins folder exists
    if os.path.isdir(plugins_path) is False:
        logger.warning("%s doesn't exists"%plugins_path)
        return {}

    # get the plugins list
    raws = [x for x in os.listdir(plugins_path) if x.startswith("plugin") and x.endswith(".py")]
    manifest = {}
    for file in raws:
        filename = os.path.join(plugins_path, file)
        plugin_str = ""
        plugin = {}
        content = ""

        # Get the whole content of the plugin
        with open(filename, "r") as fb:
            content = fb.read()
            fb.close()

        # We want the line: plugin = {"VERSION":"x.y.z", "NAME":"aaa", "TYPE": "davos"}
        lines = content.split("\n")
        for line in lines:
            if line.startswith("plugin"):
                plugin_str = line.split("=")[1]
                try:
                    # Get the plugin meta datas
                    plugin = json.loads(plugin_str)
                except:
                    pass
                finally:
                    # No need to go further
                    break

        # For file, the plugin meta are empty : next file
        if plugin == {}:
            continue
        if "TYPE" not in plugin or "NAME" not in plugin or "VERSION" not in plugin:
            continue
        if plugin["TYPE"] != "davos":
            continue

        # In davos_manifest there is the list of module_names, we will continue to use module_name

        # name = <name>
        # module_name = plugin_<name>
        # plugin_file = plugin_<name>.py
        module_name = "plugin_%s"%plugin["NAME"]
        # Davos doesn't have this plugin : add it
        if module_name not in davos_manifest:
            manifest[module_name] = plugin
            manifest[module_name]["content"] = compress_encode(content)
        else:
            # logger.debug("%s present in davos: check version %s <> %s"%(module_name, davos_manifest[module_name]["VERSION"], plugin["VERSION"]))

            # Davos has this plugin, and the davos version is higher : continue
            if compare_version(davos_manifest[module_name], plugin["VERSION"]) is False:
                # Add the plugin in the manifest
                manifest[module_name] = plugin
                manifest[module_name]["content"] = compress_encode(content)
            else:
                continue
    return manifest


def compress_encode(content):
    """Compress with zlib and encode in base64 the incoming content.

    Args:
        content (str) : the content to compress and encode

    Returns:
        str: the content compressed and encoded in base64."""

    result = base64.b64encode(zlib.compress(content.encode("utf-8"))).decode("utf-8")
    return result


def decode_decompress(content):
    """Decode base64 content string, then decompress the binary"""
    result = zlib.decompress(base64.b64decode(content)).decode("utf-8")
    return result


def compare_version(davos, canonic):
    """Compare the davos version with the canonic version. If davos is higher returns True. We can assimilate False result to : need to update

    Args:
        davos (str): davos plugin version in X.Y format
        canonic (str): canonic plugin version  in X.Y format

    Returns:
        bool: True if the davos version is higher than the canonic version. Else False.
    """
    try:
        davos = float(davos)
    except:
        davos = 0.0

    try:
        canonic = float(canonic)
    except:
        canonic = 0.0
    return davos >= canonic
