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

plugin = {"VERSION": "1.1", "NAME": "scheduling_deploy", "TYPE": "all", "SCHEDULED": True}  # fmt: skip

# nb  -1 infinie
SCHEDULE = {"schedule": "*/15 * * * *", "nb": -1}


def schedule_main(objectxmpp):
    logging.getLogger().debug("==============Plugin scheduled==============")
    logging.getLogger().debug(plugin)
    logging.getLogger().debug("============================================")
    try:
        objectxmpp.Deploybasesched.openbase()
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
            # Ouvrir un environnement de transaction
            with objectxmpp.Deploybasesched.dbsessionscheduler.begin() as txn:
                # Ouvrir un curseur pour parcourir les clés et les valeurs
                cursor = txn.cursor()

                # Parcourir toutes les paires clé-valeur
                for key, value in cursor:
                    # Convertir les données de type bytes en str (si nécessaire)
                    k = key.decode("utf-8")
                    v = value.decode("utf-8")
                    obj = json.loads(v)
                    obj["data"]["fromaction"] = obj["action"]
                    obj["action"] = "machineexecutionscheduler"
                    del obj["data"]["descriptor"]
                    del obj["data"]["packagefile"]  # ['descriptor']
                    print(json.dumps(obj, indent=4))
                    # send message to master(plugin_machineexecutionscheduler)
                    # print "SEND", json.dumps(obj, indent = 4)
                    objectxmpp.send_message(
                        mto=obj["data"]["jidmaster"],
                        mbody=json.dumps(obj),
                        mtype="chat",
                    )
    except Exception:
        logging.getLogger().error("\n%s" % (traceback.format_exc()))
    finally:
        objectxmpp.Deploybasesched.closebase()
