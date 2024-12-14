# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
this plugin charge tous les deploy scheduler, et envoi une demand d'execution a master
"""
import json
import logging
import sys
import traceback

logger = logging.getLogger()

plugin = {"VERSION": "1.2", "NAME": "scheduling_deploy", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

# nb  -1 infinie
SCHEDULE = {"schedule": "*/15 * * * *", "nb": -1}


def schedule_main(objectxmpp):
    logging.getLogger().debug("==============Plugin scheduled==============")
    logging.getLogger().debug(plugin)
    logging.getLogger().debug("============================================")
    try:
        if sys.platform.startswith("darwin"):
            for k, v in objectxmpp.Deploybasesched.dbsessionscheduler:
                obj = json.loads(v)
                obj["data"]["fromaction"] = obj["action"]
                obj["action"] = "machineexecutionscheduler"
                del obj["data"]["descriptor"]
                del obj["data"]["packagefile"]  # ['descriptor']
                print(json.dumps(obj, indent=4))
                # send message to master(plugin_machineexecutionscheduler)
                # print "SEND", json.dumps(obj, indent = 4)
                objectxmpp.send_message(
                    mto=obj["data"]["jidmaster"], mbody=json.dumps(obj), mtype="chat"
                )
        else:
            data = objectxmpp.Deploybasesched.get_all()

            for key, value in data.items():
                try:
                    if value is not None and value.strip() != "":
                        obj = json.loads(value)
                        obj["data"]["fromaction"] = obj["action"]
                        obj["action"] = "machineexecutionscheduler"
                        obj["data"].pop("descriptor", None)
                        obj["data"].pop("packagefile", None)
                        objectxmpp.send_message(
                            mto=obj["data"]["jidmaster"],
                            mbody=json.dumps(obj),
                            mtype="chat",
                        )
                    else:
                        logger.error(
                            f"The value for key '{key}' is empty or invalid, possibly missing sessionid."
                        )
                except Exception as e:
                    logger.error(f"Unexpected error : {e}")

    except Exception:
        logging.getLogger().error("\n%s" % (traceback.format_exc()))
    finally:
        objectxmpp.Deploybasesched.close()
