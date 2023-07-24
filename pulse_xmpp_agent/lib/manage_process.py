#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from .utils import decode_strconsole, encode_strconsole
import sys
import os
import json
from multiprocessing import Process, TimeoutError
import traceback
import logging
import subprocess
from threading import Timer

logger = logging.getLogger()


def processcommand(command, queue_out_session, messagestr, timeout):
    try:
        message = json.loads(messagestr)
    except BaseException:
        logger.error("\n%s" % (traceback.format_exc()))
        logging.getLogger().error("error json")
        sys.exit(0)
    try:
        # structure message for msgout
        msgoutsucces = {"eventMessageraw": message}
        logging.debug("================================================")
        logging.debug(" execution command in process")
        logging.debug("command : \n%s" % command)
        logging.debug("================================================")
        cmd = cmdx(command, timeout)
        cmddecode = decode_strconsole(cmd.stdout)
        msgoutsucces["eventMessageraw"]["data"]["codeerror"] = cmd.code_error
        msgoutsucces["eventMessageraw"]["data"]["result"] = cmddecode
        logging.debug(f"code error  {cmd.code_error}")
        logging.debug("msg succes to manager evenement: mode 'eventMessageraw'")
        queue_out_session.put(msgoutsucces)
        # logging.debug("result  %s"% cmd.stdout)
        logging.debug("================================================")

    except TimeoutError:
        logging.error(
            f'TimeoutError process  {command} sessionid : {message["sessionid"]}'
        )
    except KeyboardInterrupt:
        logging.warning(
            f'KeyboardInterrupt process  {command} sessionid : {message["sessionid"]}'
        )
        sys.exit(0)
    except BaseException:
        logger.error("\n%s" % (traceback.format_exc()))
        logging.error(
            f'error execution process {command} sessionid : {message["sessionid"]}'
        )
        sys.exit(0)


def processstepcommand(command, queue_out_session, messagestr, timeout, step):
    command = decode_strconsole(command)
    try:
        message = json.loads(decode_strconsole(messagestr))
    except BaseException:
        logger.error("\n%s" % (traceback.format_exc()))
        logging.getLogger().error("error json")
        sys.exit(0)

    try:
        sequence = message["data"]["descriptor"]["sequence"]
        workingstep = next((i for i in sequence if i["step"] == step), {})
        ###
        if len(workingstep) != 0:
            # structure message for msgout
            logging.getLogger().debug(
                "================================================"
            )
            logging.getLogger().debug(" execution command in process")
            logging.getLogger().debug(f"command : {command}")
            logging.getLogger().debug(
                "================================================"
            )
            cmd = cmdx(command, timeout)
            workingstep["codereturn"] = cmd.code_error
            message["data"]["oldreturncode"] = str(cmd.code_error)
            workingstep["completed"] = 1
            cmddecode = decode_strconsole(cmd.stdout)
            result = cmddecode.split("\n")
            result = [x.strip() for x in result if x != ""]
            try:
                message["data"]["oldresult"] = decode_strconsole(str(result[-1]))
            except BaseException:
                message["data"]["oldresult"] = ""
            for t in workingstep:
                if t == "@resultcommand":
                    workingstep[t] = os.linesep.join(result)
                elif t.endswith("lastlines"):
                    nb = t.split("@")
                    nb1 = -int(nb[0])
                    logging.getLogger().debug(
                        f"=======lastlines============{nb1}========"
                    )
                    workingstep[t] = os.linesep.join(result)
                elif t.endswith("firstlines"):
                    nb = t.split("@")
                    nb1 = int(nb[0])
                    logging.getLogger().debug(
                        f"=======firstlines============{nb1}======="
                    )
                    workingstep[t] = os.linesep.join(result)
            if "goto" in workingstep:
                message["data"]["stepcurrent"] = workingstep["goto"]
            elif "success" in workingstep and workingstep["codereturn"] == 0:
                message["data"]["stepcurrent"] = workingstep["success"]
            elif "error" in workingstep and workingstep["codereturn"] != 0:
                message["data"]["stepcurrent"] = workingstep["error"]
            else:
                message["data"]["stepcurrent"] = message["data"]["stepcurrent"] + 1

            logging.getLogger().debug(f'Next Step : {message["data"]["stepcurrent"]}')
            msgoutsucces = {"eventMessageraw": message}

            msgoutsucces["eventMessageraw"]["data"]["codeerror"] = cmd.code_error
            queue_out_session.put(msgoutsucces)
        else:
            logging.getLogger().debug(
                "######MESSAGE error#############\n%s"
                % json.dumps(message, indent=4, sort_keys=True)
            )

    except TimeoutError:
        logging.getLogger().error(
            f'TimeoutError process  {command} sessionid : {message["sessionid"]}'
        )
    except KeyboardInterrupt:
        logging.getLogger().warning(
            f'KeyboardInterrupt process  {command} sessionid : {message["sessionid"]}'
        )
        sys.exit(0)
    except BaseException:
        logger.error("\n%s" % (traceback.format_exc()))
        logging.getLogger().error(
            f'error execution process {command} sessionid : {message["sessionid"]}'
        )
        sys.exit(0)


class process_on_end_send_message_xmpp:
    def __init__(self, queue_out_session):
        self.processtable = []
        self.queue_out_session = queue_out_session
        logging.debug("manage process start")

    def add_processcommand(
        self, command, message, tosucces=None, toerror=None, timeout=50, step=None
    ):
        message["data"]["tosucces"] = tosucces
        message["data"]["toerror"] = toerror
        messagestr = json.dumps(message)

        if not (step is None or isinstance(step, int)):
            logging.error("Error Descriptor Step in not Integer")
            return False
        if tosucces is None and toerror is None:
            logging.error("any agent to process result from queue")
            return False

        message["data"]["tosucces"] = tosucces
        message["data"]["toerror"] = toerror

        if step is None:
            createprocesscommand = Process(
                target=processcommand,
                args=(command, self.queue_out_session, messagestr, timeout),
            )
            createprocesscommand.start()
        else:
            createprocessstepcommand = Process(
                target=processstepcommand,
                args=(command, self.queue_out_session, messagestr, timeout, step),
            )
            createprocessstepcommand.start()

        return True

    def processstepcommand(self, command, queue_out_session, messagestr, timeout, step):
        logging.getLogger().error("########processstepcommand")
        try:
            message = json.loads(messagestr)
        except BaseException:
            logger.error("\n%s" % (traceback.format_exc()))
            logging.getLogger().error("error json")
            sys.exit(0)

        try:
            sequence = message["data"]["descriptor"]["sequence"]
            workingstep = next((i for i in sequence if i["step"] == step), {})
            if len(workingstep) != 0:
                # structure message for msgout
                logging.getLogger().debug(
                    "================================================"
                )
                logging.getLogger().debug(" execution command in process")
                logging.getLogger().debug(f"command : {command}")
                logging.getLogger().debug(
                    "================================================"
                )
                cmd = cmdx(command, timeout)
                workingstep["codereturn"] = cmd.code_error
                workingstep["completed"] = 1
                cmddecode = decode_strconsole(cmd.stdout)
                result = cmddecode.split("\n")
                result = [x.strip() for x in result if x != ""]
                for t in workingstep:
                    if t == "@resultcommand":
                        workingstep[t] = os.linesep.join(result)
                    elif t.endswith("lastlines"):
                        nb = t.split("@")
                        nb1 = -int(nb[0])
                        logging.getLogger().debug(
                            f"=======lastlines============{nb1}========"
                        )
                        tab = result[nb1:]
                        workingstep[t] = os.linesep.join(tab)
                    elif t.endswith("firstlines"):
                        nb = t.split("@")
                        nb1 = int(nb[0])
                        logging.getLogger().debug(
                            f"=======firstlines============{nb1}======="
                        )
                        tab = result[:nb1]
                        workingstep[t] = os.linesep.join(tab)
                if "goto" in workingstep:
                    message["data"]["stepcurrent"] = workingstep["goto"]
                elif "succes" in workingstep and workingstep["codereturn"] == 0:
                    message["data"]["stepcurrent"] = workingstep["succes"]
                elif "error" in workingstep and workingstep["codereturn"] != 0:
                    message["data"]["stepcurrent"] = workingstep["error"]
                else:
                    message["data"]["stepcurrent"] = message["data"]["stepcurrent"] + 1

                logging.getLogger().debug(
                    f'Next Step : {message["data"]["stepcurrent"]}'
                )
                msgoutsucces = {"eventMessageraw": message}

                msgoutsucces["eventMessageraw"]["data"]["codeerror"] = cmd.code_error
                queue_out_session.put(msgoutsucces)
            else:
                logging.getLogger().debug(
                    "######MESSAGE error#############\n%s"
                    % json.dumps(message, indent=4, sort_keys=True)
                )

        except TimeoutError:
            logging.getLogger().error(
                f'TimeoutError process  {command} sessionid : {message["sessionid"]}'
            )
        except KeyboardInterrupt:
            logging.getLogger().warning(
                f'KeyboardInterrupt process  {command} sessionid : {message["sessionid"]}'
            )
            sys.exit(0)
        except BaseException:
            logger.error("\n%s" % (traceback.format_exc()))
            logging.getLogger().error(
                f'error execution process {command} sessionid : {message["sessionid"]}'
            )
            sys.exit(0)

    def terminateprocess(self, p):
        p.terminate()

    def processcommand(self, command, queue_out_session, messagestr, timeout):
        logging.error("########processcommand")
        try:
            message = json.loads(decode_strconsole(messagestr))
        except BaseException:
            logger.error("\n%s" % (traceback.format_exc()))
            logging.getLogger().error("error json")
            sys.exit(0)
        try:
            # structure message for msgout
            msgoutsucces = {"eventMessageraw": message}
            logging.debug("================================================")
            logging.debug(" execution command in process")
            logging.debug(f"command : {command}")
            logging.debug("================================================")
            cmd = cmdx(command, timeout)
            msgoutsucces["eventMessageraw"]["data"]["codeerror"] = cmd.code_error
            cmddecode = decode_strconsole(cmd.stdout)
            msgoutsucces["eventMessageraw"]["data"]["result"] = cmddecode
            logging.debug(f"code error  {cmd.code_error}")
            logging.debug("msg succes to manager evenement: mode 'eventMessageraw'")
            queue_out_session.put(msgoutsucces)
            # logging.debug("code error  %s"% cmd.code_error)
            # logging.debug("result  %s"% cmd.stdout)
            logging.debug("================================================")

        except TimeoutError:
            logging.error(
                f'TimeoutError process  {command} sessionid : {message["sessionid"]}'
            )
        except KeyboardInterrupt:
            logging.warning(
                f'KeyboardInterrupt process  {command} sessionid : {message["sessionid"]}'
            )
            sys.exit(0)
        except BaseException:
            logger.error("\n%s" % (traceback.format_exc()))
            logging.error(
                f'error execution process {command} sessionid : {message["sessionid"]}'
            )
            sys.exit(0)


class mannageprocess:
    def __init__(self, queue_out_session):
        self.processtable = []
        self.queue_out_session = queue_out_session
        logging.debug("manage process start")

    def add_processcommand(
        self,
        command,
        sessionid,
        eventstart=False,
        eventfinish=False,
        eventerror=False,
        timeout=50,
        keysdescriptor=[],
    ):
        createprocesscommand = Process(
            target=self.processcommand,
            args=(
                command,
                self.queue_out_session,
                sessionid,
                eventstart,
                eventfinish,
                eventerror,
                timeout,
                keysdescriptor,
            ),
        )
        self.processtable.append(createprocesscommand)
        createprocesscommand.start()

    def processcommand(
        self,
        command,
        queue_out_session,
        sessionid,
        eventstart,
        eventfinish,
        eventerror,
        timeout,
        keysdescriptor,
    ):
        # il y a 2 types de messages event ceux de la boucle interne et ceux
        # envoyé en TEVENT
        try:
            # structure message for msgout
            msgout = {
                "event": "",
                "sessionid": sessionid,
                "result": {
                    "codeerror": 0,
                    "resultcommand": "",
                    "command": decode_strconsole(command),
                },
            }
            if eventstart is not False:
                # ecrit dans queue_out_session l'evenement eventstart
                if "_eventype" in eventstart and "_eventype" == "TEVENT":
                    msgout["event"] = eventstart
                    queue_out_session.put(msgout)
                else:
                    queue_out_session.put(eventstart)
            cmd = cmdx(command, timeout)
            cmddecode = decode_strconsole(cmd.stdout)
            if cmd.code_error == 0 and eventfinish is not False:
                ev = eventfinish
            elif cmd.code_error != 0 and eventfinish is not False:
                ev = eventerror
            else:
                ev = False
            logging.debug("================================================")
            logging.debug(" execution command in process")
            logging.debug("================================================")

            if ev is not False:
                if "_eventype" in ev and "_eventype" == "TEVENT":
                    # ecrit dans queue_out_session le TEVENT
                    msgout["event"] = ev
                    # msgout['result']['resultcommand'] = cmd['result']
                    msgout["result"]["resultcommand"] = cmddecode
                    msgout["result"]["codeerror"] = cmd.code_error
                    queue_out_session.put(msgout)
                else:
                    # "10@firstlines" : "",
                    # "10@lastlines": "",
                    # "@resultcommand":""

                    # ev['data']['result'] = {'codeerror': cmd['code'],'resultcommand': cmd['result'],'command': command  }
                    ev["data"]["result"] = {
                        "codeerror": cmd.code_error,
                        "command": command,
                    }
                    for t in keysdescriptor:
                        if t in ["codeerror", "command"]:
                            pass
                        elif t == "@resultcommand":
                            ev["data"]["result"]["@resultcommand"] = cmd.stdout
                        elif t.endswith("lastlines"):
                            nb = t.split("@")
                            nb1 = -int(nb[0])
                            tab = [x for x in cmd.stdout.split(os.linesep) if x != ""]
                            tab = tab[nb1:]
                            ev["data"]["result"][t] = os.linesep.join(tab)
                        elif t.endswith("firstlines"):
                            nb = t.split("@")
                            nb1 = int(nb[0])
                            tab = [x for x in cmd.stdout.split(os.linesep) if x != ""]
                            tab = tab[:nb1]
                            ev["data"]["result"][t] = os.linesep.join(tab)
                    queue_out_session.put(ev)
        except TimeoutError:
            logging.error(f"TimeoutError process  {command} sessionid : {sessionid}")
        except KeyboardInterrupt:
            logging.warning(
                f"KeyboardInterrupt process  {command} sessionid : {sessionid}"
            )
            sys.exit(0)
        except BaseException:
            logger.error("\n%s" % (traceback.format_exc()))
            logging.error(f"error execution process {command} sessionid : {sessionid}")
            sys.exit(0)


class cmdx(object):
    def __init__(self, cmd, timeout):
        self.cmd = encode_strconsole(cmd)
        try:
            self.timeout = int(timeout)
        except BaseException:
            logging.warning("parameter timeout error. timeout 800s")
            self.timeout = 800
        self.timeoutbool = False
        self.code_error = 0
        self.run()

    def kill_proc(self, proc):
        self.timeoutbool = True
        proc.kill()

    def run(self):
        self.proc = subprocess.Popen(
            self.cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        # kill_proc = lambda p: p.kill()
        timer = Timer(self.timeout, self.kill_proc, [self.proc])
        try:
            timer.start()
            stdout, stderr = self.proc.communicate()
        finally:
            timer.cancel()
        # self.stderr = stderr
        self.stdout = decode_strconsole(stdout)

        self.code_error = self.proc.returncode
        if self.timeoutbool:
            self.stdout = f"error : timeout {self.timeout}"
