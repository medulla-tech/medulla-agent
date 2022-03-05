#!/usr/bin/python3
# -*- coding: utf-8; -*-
#
# (c) 2016-2018 siveo, http://www.siveo.net
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
# file pluginsmastersubstitute/plugin_vectormonitoringagent.py
import sys
import json
import logging


import traceback
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()

plugin = {"VERSION": "1.4", "NAME": "vectormonitoringagent", "TYPE": "substitute"}


class DateTimeEncoder(json.JSONEncoder):
    """
    Used to hanld datetime in json files.
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            encoded_object = obj.isoformat()
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object


def process_system(
    functionname,
    xmppobject,
    msg_from,
    sessionid,
    data,
    id_machine,
    hostname,
    platform,
    agenttype,
    statusmsg,
    id_mon_machine,
):
    device_type = functionname[8:]
    logger.debug("Device %s" % device_type)
    serial, status, firmware, alarm_msg = ["", "ready", "", []]
    if "serial" in data:
        serial = data["serial"]
        del data["serial"]
    if "status" in data and data["status"] != "":
        status = data["status"]
        del data["status"]
    if "firmware" in data:
        firmware = data["firmware"]
        del data["firmware"]
    if "alarms" in data:
        if isinstance(data["alarms"], basestring):
            alarm_msg = [data["alarms"]]
        elif isinstance(data["alarms"], list):
            alarm_msg = data["alarms"]
        del data["alarms"]
    logger.debug(
        "(system) call setMonitoring_device_reg hostname %s\n"
        " id_machine %s \n"
        " platform %s \n"
        " agenttype %s \n"
        " statusmsg %s \n"
        " id_mon_machine %s \n"
        " device_type, %s\n"
        " serial %s \n"
        " firmware %s\n"
        " status %s\n"
        " alarm_msg %s\n"
        " metriques %s"
        % (
            hostname,
            id_machine,
            platform,
            agenttype,
            statusmsg,
            id_mon_machine,
            device_type,
            serial,
            firmware,
            status,
            json.dumps(alarm_msg),
            json.dumps(data["metriques"]),
        )
    )
    a = XmppMasterDatabase().setMonitoring_device_reg(
        hostname,
        id_machine,
        platform,
        agenttype,
        statusmsg,
        xmppobject,
        msg_from,
        sessionid,
        id_mon_machine,
        device_type,
        serial,
        firmware,
        status,
        json.dumps(alarm_msg),
        json.dumps(data["metriques"]),
    )
    return a


def process_nfcreader(
    functionname,
    xmppobject,
    msg_from,
    sessionid,
    data,
    id_machine,
    hostname,
    platform,
    agenttype,
    statusmsg,
    id_mon_machine,
):
    device_type = functionname[8:]
    serial, status, firmware, alarm_msg = ["", "ready", "", []]
    if "serial" in data:
        serial = data["serial"]
        del data["serial"]
    if "status" in data and data["status"] != "":
        status = data["status"]
        del data["status"]
    if "firmware" in data:
        firmware = data["firmware"]
        del data["firmware"]
    if "message" in data:
        if isinstance(data["message"], basestring):
            alarm_msg = [data["message"]]
        elif isinstance(data["message"], list):
            alarm_msg = data["message"]
        del data["message"]
    logger.debug(
        "(nfcreader) call setMonitoring_device_reg hostname %s\n"
        " id_machine %s \n"
        " platform %s \n"
        " agenttype %s \n"
        " statusmsg %s \n"
        " id_mon_machine %s \n"
        " device_type, %s\n"
        " serial %s \n"
        " firmware %s\n"
        " status %s\n"
        " alarm_msg %s\n"
        " metriques %s"
        % (
            hostname,
            id_machine,
            platform,
            agenttype,
            statusmsg,
            id_mon_machine,
            device_type,
            serial,
            firmware,
            status,
            json.dumps(alarm_msg),
            json.dumps(data["metriques"]),
        )
    )
    a = XmppMasterDatabase().setMonitoring_device_reg(
        hostname,
        id_machine,
        platform,
        agenttype,
        statusmsg,
        xmppobject,
        msg_from,
        sessionid,
        id_mon_machine,
        device_type,
        serial,
        firmware,
        status,
        json.dumps(alarm_msg),
        json.dumps(data["metriques"]),
    )


def process_generic(
    functionname,
    xmppobject,
    msg_from,
    sessionid,
    data,
    id_machine,
    hostname,
    platform,
    agenttype,
    statusmsg,
    id_mon_machine,
):
    device_type = functionname[8:]
    logger.debug("Device %s" % device_type)
    serial, status, firmware, alarm_msg = ["", "ready", "", []]
    if "serial" in data:
        serial = data["serial"]
        del data["serial"]
    if "status" in data and data["status"] != "":
        status = data["status"]
        del data["status"]
    if "firmware" in data:
        firmware = data["firmware"]
        del data["firmware"]
    if "message" in data:
        if isinstance(data["message"], basestring):
            alarm_msg = [data["message"]]
        elif isinstance(data["message"], list):
            alarm_msg = data["message"]
        del data["message"]
    logger.debug(
        "(generic) call setMonitoring_device_reg hostname %s\n"
        " id_machine %s \n"
        " platform %s \n"
        " agenttype %s \n"
        " statusmsg %s \n"
        " id_mon_machine %s \n"
        " device_type, %s\n"
        " serial %s \n"
        " firmware %s\n"
        " status %s\n"
        " alarm_msg %s\n"
        " metriques %s"
        % (
            hostname,
            id_machine,
            platform,
            agenttype,
            statusmsg,
            id_mon_machine,
            device_type,
            serial,
            firmware,
            status,
            json.dumps(alarm_msg),
            json.dumps(data["metriques"]),
        )
    )
    a = XmppMasterDatabase().setMonitoring_device_reg(
        hostname,
        id_machine,
        platform,
        agenttype,
        statusmsg,
        xmppobject,
        msg_from,
        sessionid,
        id_mon_machine,
        device_type,
        serial,
        firmware,
        status,
        json.dumps(alarm_msg),
        json.dumps(data["metriques"]),
    )


def callFunction(functionname, *args, **kwargs):
    functionname = "process_%s" % functionname.lower()
    logger.debug("**call function %s %s %s" % (functionname, args, kwargs))
    thismodule = sys.modules[__name__]
    try:
        return getattr(thismodule, functionname)(functionname, *args, **kwargs)
    except AttributeError:
        logger.debug("call generic process_generic")
        return process_generic(functionname, *args, **kwargs)
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("Start sessionid %s " % sessionid)
    logger.debug("call plugin %s from %s" % (plugin, message["from"]))
    action_msg = json.dumps(data, indent=4)
    logger.debug(action_msg)
    logger.debug("#################################################")

    compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
    logger.debug("compteur num_call plugin %s %s" % (action, compteurcallplugin))

    if compteurcallplugin == 0:
        xmppobject.typelistMonitoring_device = (
            XmppMasterDatabase().getlistMonitoring_devices_type()
        )
        logger.debug("list device %s" % (xmppobject.typelistMonitoring_device))

    machine = XmppMasterDatabase().getMachinefromjid(message["from"])
    statusmsg = {"mon_status": ""}  # , 'mon_subject' : "", 'mon_param0' : ""
    if "status" in data:
        statusmsg["mon_status"] = data["status"]
    if "other_data" in data:
        statusmsg["other_data"] = data["other_data"]
    logger.debug("Machine %s %s" % (machine["id"], machine["hostname"]))
    if "subaction" in data and data["subaction"].lower() in [
        "terminalinformations",
        "terminalalert",
    ]:

        logger.debug("package json correct %s" % (data["subaction"]))
        id_mom_machine = XmppMasterDatabase().setMonitoring_machine(
            machine["id"],
            machine["hostname"],
            date=data["date"],
            statusmsg=json.dumps(statusmsg, cls=DateTimeEncoder),
        )
        # for each device/service call process
        if "device_service" in data:
            for element in data["device_service"]:
                for devicename in element:
                    # call process functions defined
                    devicename = devicename
                    logger.debug("devicename %s" % (devicename))
                    if devicename.lower() in xmppobject.typelistMonitoring_device:
                        if devicename in element:
                            if "subject" in element[devicename]:
                                statusmsg["mon_subject"] = element[devicename][
                                    "subject"
                                ]
                            if "param0" in element[devicename]:
                                statusmsg["mon_param0"] = element[devicename]["param0"]
                        result = callFunction(
                            devicename,
                            xmppobject,
                            str(message["from"]),
                            sessionid,
                            element[devicename],
                            machine["id"],
                            machine["hostname"],
                            machine["platform"],
                            machine["agenttype"],
                            statusmsg,
                            id_mom_machine,
                        )
                        if result == -1:
                            logger.warning(
                                "[%s] verify message alert from %s"
                                % (sessionid, message["from"])
                            )
                            logger.warning(
                                "[%s] binding peut etre pas resolue" % sessionid
                            )
                            logger.warning(action_msg)
    logger.debug("####end sessionid %s ####" % sessionid)
