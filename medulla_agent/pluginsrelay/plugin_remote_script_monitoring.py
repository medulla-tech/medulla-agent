#!/usr/bin/python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin dploys a script received by a substitute on the client and execute it.
The result of the script is sent back the substitute's result plugin.
"""

import json
import traceback
import logging
import zlib
import os
import sys
import base64
from lib.utils import (
    decode_strconsole,
    encode_strconsole,
    powerschellscriptps1,
    simplecommandstr,
)

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "remote_script_monitoring", "VERSIONAGENT": "2.0.0", "TYPE": "all"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    data_return = {
        "action": "result" + action,
        "data": {"result_script": ""},
        "sessionid": sessionid,
        "ret": 255,
        "base64": False,
    }
    try:
        logger.debug("###################################################")
        logger.debug(
            "call %s from %s session id %s" % (plugin, message["from"], sessionid)
        )
        logger.debug("###################################################")
        logger.debug(json.dumps(data, indent=4))

        # file_result is the file where the result have to be written
        if "file_result" in data:
            data_return["data"]["file_result"] = data["file_result"]
        else:
            data_return["data"]["result_script"] = "error file"
            raise

        if "script_data" in data:
            strctfilestr = ""
            try:
                strctfilestr = zlib.decompress(base64.b64decode(data["script_data"]))
            except Exception as e:
                result_script = "%s" % (traceback.format_exc())
                data_return["data"]["result_script"] = result_script
                raise
        else:
            data_return["data"]["result_script"] = "script missing"
            raise

        if strctfilestr:
            # we copy the script in tmp (depending of the OS)
            if sys.platform.startswith("linux"):
                tempdir = "/tmp"
            elif sys.platform.startswith("win"):
                tempdir = os.getenv("temp")
                tmpdir = os.path.join("c:\progra~1", "medulla", "tmp")
            elif sys.platform.startswith("darwin"):
                tempdir = "/tmp"
            else:
                data_return["data"]["result_script"] = "os NotImplemented"
                raise
        else:
            data_return["data"]["result_script"] = "script empty"
            raise

        if "name_script" in data:
            dataencode = encode_strconsole(strctfilestr)
            path_file = os.path.join(tempdir, data["name_script"])
            with open(path_file, "wb") as f:
                datafile = f.write(dataencode)
        else:
            data_return["data"]["result_script"] = "name_script empty"
            raise

        # Execution of the script
        # Treatment of the script of the remove machine
        # path_file: Name of the file
        obj = None
        if "type_script" in data:
            if data["type_script"].startswith("python"):
                obj = simplecommandstr("%s %s" % (data["type_script"], path_file))
            elif data["type_script"].startswith("bash"):
                if sys.platform.startswith("linux") or sys.platform.startswith(
                    "darwin"
                ):
                    obj = simplecommandstr("/bin/bash %s" % path_file)
                else:
                    obj["code"] = -1
                    obj["result"] = (
                        "command bash"
                        "on linux and darwin only\nplatform is %s" % sys.platform
                    )
            elif data["type_script"].startswith("cshell"):
                if sys.platform.startswith("linux") or sys.platform.startswith(
                    "darwin"
                ):
                    obj = simplecommandstr("/bin/csh %s" % path_file)
                else:
                    obj["code"] = -1
                    obj["result"] = (
                        "command cshell"
                        "on linux and darwin only\nplatform is %s" % sys.platform
                    )
            elif data["type_script"].startswith("Kornshell"):
                if sys.platform.startswith("linux") or sys.platform.startswith(
                    "darwin"
                ):
                    obj = simplecommandstr("/bin/ksh %s" % path_file)
                else:
                    obj["code"] = -1
                    obj["result"] = (
                        "command Kornshell"
                        "on linux and darwin only\nplatform is %s" % sys.platform
                    )
            elif data["type_script"].startswith("powershell"):
                if sys.platform.startswith("win"):
                    obj = powerschellscriptps1(path_file)
                else:
                    obj["code"] = -1
                    obj["result"] = (
                        "command powershell"
                        "on window only\nplatform is %s" % sys.platform
                    )
            elif data["type_script"].startswith("batch"):
                if sys.platform.startswith("win"):
                    path_file1 = path_file + ".bat"
                    os.rename(path_file, path_file1)
                    obj = simplecommandstr("%s" % (path_file1))
                else:
                    obj["code"] = -1
                    obj["result"] = (
                        "command dos file .bat"
                        "on window only\nplatform is %s" % sys.platform
                    )
        else:
            data_return["data"]["result_script"] = "type_script missing"
            raise

        if obj:
            data_return["ret"] = 0
            decoderesult = decode_strconsole(obj["result"])
            data_return["data"]["result_script"] = base64.b64encode(
                zlib.compress(decoderesult, 9)
            )
            data_return["data"]["return_code"] = obj["code"]
            objectxmpp.send_message(
                mto=message["from"], mbody=json.dumps(data_return), mtype="chat"
            )
        else:
            data_return["data"]["result_script"] = "resultat missing"
            raise
    except:
        logger.error("%s" % (traceback.format_exc()))
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(data_return), mtype="chat"
        )
