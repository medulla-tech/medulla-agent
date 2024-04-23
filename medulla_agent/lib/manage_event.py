#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from multiprocessing import TimeoutError
import threading
from .utils import getRandomName, call_plugin
from slixmpp import jid
import logging

logger = logging.getLogger()


class manage_event:
    def __init__(self, queue_in, objectxmpp):
        self.event = []
        self.queue_in = queue_in
        self.namethread = getRandomName(5, "threadevent")
        self.objectxmpp = objectxmpp
        self.threadevent = threading.Thread(
            name=self.namethread, target=self.manage_event_command
        )
        self.threadevent.start()
        logging.debug("manage event start")

    def show_eventloop(self):
        for i in self.event:
            print("------------\n%s\n------------" % i)

    def addevent(self, event):
        self.event.append(event)

    def delevent(self, event):
        self.event.append(event)

    @staticmethod
    def create_TEVENT(to, action, sessionid, devent):
        return {
            "to": to,
            "action": action,
            "sessionid": sessionid,
            "data": {"Dtypequery": "TEVENT", "Devent": devent},
            "ret": 0,
            "base64": False,
            "_eventype": "TEVENT",
        }

    @staticmethod
    def create_EVENT(to, action, sessionid, Dtypequery, devent, ret=0, base64=False):
        return {
            "to": to,
            "action": action,
            "sessionid": sessionid,
            "data": {"Dtypequery": "TR", "Devent": devent},
            "ret": ret,
            "base64": base64,
        }

    @staticmethod
    def create_EVENT_TR(to, action, sessionid, devent):
        return {
            "to": to,
            "action": action,
            "sessionid": sessionid,
            "data": {"Dtypequery": "TR", "Devent": devent},
            "ret": 0,
            "base64": False,
        }

    @staticmethod
    def create_EVENT_ERR(to, action, sessionid, devent):
        return {
            "to": to,
            "action": action,
            "sessionid": sessionid,
            "data": {"Dtypequery": "TE", "Devent": devent},
            "ret": 125,
            "base64": False,
        }

    def manage_event_loop(self):
        # traitement message interne
        for i in self.event:
            if "event" not in i:
                # message de type loop
                jidto = jid.JID(str(i["to"])).bare
                msg = {
                    "from": jidto,
                    "to": jidto,
                    "body": {
                        "ret": i["ret"],
                        "sessionid": i["sessionid"],
                        "base64": False,
                    },
                }
                if (
                    self.objectxmpp.session.isexist(i["sessionid"])
                    and jidto == self.objectxmpp.boundjid.bare
                ):
                    # call plugin i['sessionid'] == msg['from'].bare
                    call_plugin(
                        i["action"],
                        self.objectxmpp,
                        i["action"],
                        i["sessionid"],
                        i["data"],
                        msg,
                        {},
                    )

    def delmessage_loop(self, devent):
        # supprime message loop devent
        for i in self.event:
            if "event" not in i:
                if i["data"]["Devent"] == devent:
                    self.event.remove(i)
                    break

    def delmessage_loop_Dtypequery(self, Dtypequery):
        # supprime message loop devent
        for i in self.event:
            if "event" not in i:
                if i["data"]["Dtypequery"] == Dtypequery:
                    self.event.remove(i)
                    break

    def clear(self, sessionid):
        self.event = [x for x in self.event if x["sessionid"] != sessionid]

    def manage_event_command(self):
        logging.debug("loop event wait start")
        try:
            while True:
                try:
                    # lit event
                    event = self.queue_in.get(5)
                    if event == "quit":
                        break
                    if "eventMessageraw" in event:
                        message = event["eventMessageraw"]
                        recipienterror = message["data"]["toerror"]
                        recipientsucces = message["data"]["tosucces"]
                        del message["data"]["tosucces"]
                        del message["data"]["toerror"]
                        codeerror = int(message["data"]["codeerror"])
                        if (
                            recipienterror is not None
                            and message["data"]["codeerror"] != 0
                        ):
                            del message["data"]["codeerror"]
                            self.objectxmpp.send_message(
                                mto=recipienterror,
                                mbody=json.dumps(message),
                                mtype="chat",
                            )
                        elif recipientsucces is not None:
                            del message["data"]["codeerror"]
                            self.objectxmpp.send_message(
                                mto=recipientsucces,
                                mbody=json.dumps(message),
                                mtype="chat",
                            )

                        if (
                            "data" in event["eventMessageraw"]
                            and "descriptor" in event["eventMessageraw"]["data"]
                            and "sequence"
                            in event["eventMessageraw"]["data"]["descriptor"]
                        ):
                            # search workingstep for message log to log service
                            # et log to syslog
                            if "stepcurrent" in event["eventMessageraw"]["data"]:
                                nb_currentworkingset = (
                                    int(event["eventMessageraw"]["data"]["stepcurrent"])
                                    - 1
                                )
                                for i in event["eventMessageraw"]["data"]["descriptor"][
                                    "sequence"
                                ]:
                                    if int(i["step"]) == nb_currentworkingset:
                                        i["codereturn"] = codeerror
                                        logging.debug(
                                            "deploy [process command : %s ]\n%s"
                                            % (
                                                event["eventMessageraw"]["sessionid"],
                                                json.dumps(i, indent=4, sort_keys=True),
                                            )
                                        )
                                        if "command" in i:
                                            log_class = (
                                                "log_ok"
                                                if i["codereturn"] == 0
                                                else "log_err"
                                            )
                                            self.objectxmpp.xmpplog(
                                                f'[{event["eventMessageraw"]["data"]["name"]}]-[{i["step"]}]:<span class="{log_class}"> [Process command] errorcode {i["codereturn"]} forcommand : {i["command"][:20]} <span>',
                                                type="deploy",
                                                sessionname=event["eventMessageraw"][
                                                    "sessionid"
                                                ],
                                                priority=i["step"],
                                                action="xmpplog",
                                                who=self.objectxmpp.boundjid.bare,
                                                how="",
                                                why="",
                                                module="Deployment | Error | Execution",
                                                date=None,
                                                fromuser=event["eventMessageraw"][
                                                    "data"
                                                ]["login"],
                                                touser="",
                                            )
                                        else:
                                            self.objectxmpp.xmpplog(
                                                f'[{i["step"]}]: {i["action"]} ',
                                                type="deploy",
                                                sessionname=event["eventMessageraw"][
                                                    "sessionid"
                                                ],
                                                priority=i["step"],
                                                action="xmpplog",
                                                who=self.objectxmpp.boundjid.bare,
                                                how="",
                                                why="",
                                                module="Deployment | Execution",
                                                date=None,
                                                fromuser=event["eventMessageraw"][
                                                    "data"
                                                ]["login"],
                                                touser="",
                                            )
                                        break
                        continue

                    self.show_eventloop()
                    if "sessionid" in event and "_eventype" in event:
                        if (
                            "result" in event["data"]
                            and "command" in event["data"]["result"]
                            and "codeerror" in event["data"]["result"]
                            and "Dtypequery" in event["data"]["result"]
                            and "Devent" in event["data"]["result"]
                        ):
                            msg = {
                                "ret": event["ret"],
                                "sessionid": event["sessionid"],
                                "base64": event["base64"],
                                "action": event["action"],
                                "data": {
                                    "resultcommand": event["data"]["result"][
                                        "resultcommand"
                                    ],
                                    "command": event["data"]["result"]["command"],
                                    "codeerror": event["data"]["result"]["codeerror"],
                                    "Dtypequery": event["data"]["Dtypequery"],
                                    "Devent": event["data"]["Devent"],
                                },
                            }
                        else:
                            msg = {
                                "ret": event["ret"],
                                "sessionid": event["sessionid"],
                                "base64": event["base64"],
                                "action": event["action"],
                                "data": {
                                    "Dtypequery": event["data"]["Dtypequery"],
                                    "Devent": event["data"]["Devent"],
                                },
                            }
                        self.objectxmpp.send_message(
                            mto=event["to"], mbody=json.dumps(msg), mtype="chat"
                        )
                    else:
                        if "sessionid" in event:
                            event["data"] = dict(
                                list(
                                    self.objectxmpp.session.sessionfromsessiondata(
                                        event["sessionid"]
                                    ).datasession.items()
                                )
                                + list(event["data"].items())
                            )
                        self.addevent(event)
                except TimeoutError:
                    print("TimeoutError")

        except KeyboardInterrupt:
            pass
        finally:
            logging.info("loop event wait stop")
