# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import glob
import os
import json
import logging
from .utils import loadjsonfile
from os import listdir
import time
import traceback


def clean_session(folder_session):
    tt = time.time()
    SessionFiles = [
        os.path.join(folder_session, f)
        for f in listdir(folder_session)
        if len(f) == 25 and os.path.isfile(os.path.join(folder_session, f))
    ]
    for File in SessionFiles:
        creation = os.path.getmtime(File)
        try:
            with open(File) as json_data:
                data_dict = json.load(json_data)
            if (data_dict["timevalid"] + creation) < tt:
                os.remove(File)
        except BaseException:
            os.remove(File)
            errorstr = f"{traceback.format_exc()}"


class Session(Exception):
    pass


class SessionAssertion(Session, AssertionError):
    pass


class Sessionpathsauvemissing(Session, Exception):
    pass


class SessionkeyError(Session, KeyError):
    pass


class sessiondatainfo:
    def __init__(
        self,
        sessionid,
        datasession=None,
        timevalid=10,
        eventend=None,
        handlefunc=None,
        pathfile=None,
    ):
        if datasession is None:
            datasession = {}
        self.sessionid = sessionid
        self.timevalid = timevalid
        self.datasession = datasession
        self.eventend = eventend
        self.handlefunc = handlefunc
        self.pathfile = pathfile
        if pathfile is None:
            raise Sessionpathsauvemissing
        logging.getLogger().debug("Creation manager session")

    def jsonsession(self):
        session = {
            "sessionid": self.sessionid,
            "timevalid": self.timevalid,
            "datasession": self.datasession,
        }
        return json.dumps(session)

    def sauvesession(self):
        """
        Create file with the sessionid in the name.
        It saves the file in the python medulla_master_substitute folder.
        Return:
            It returns True if the file is well created.
            False, otherwise
        """
        namefilesession = os.path.join(self.pathfile, self.sessionid)
        logging.getLogger().debug(f"Create session: {self.sessionid}")
        session = {
            "sessionid": self.sessionid,
            "timevalid": self.timevalid,
            "datasession": self.datasession,
        }
        try:
            with open(namefilesession, "w") as f:
                json.dump(session, f, indent=4)
            return True
        except Exception as e:
            logging.getLogger().error(
                f"We encountered an issue while creating the session {namefilesession}"
            )
            logging.getLogger().error(f"The error is {str(e)}")
            if os.path.isfile(namefilesession):
                os.remove(namefilesession)
            return False
        return True

    def updatesessionfromfile(self):
        namefilesession = os.path.join(self.pathfile, self.sessionid)
        logging.getLogger().debug("UPDATE SESSION")
        try:
            session = loadjsonfile(namefilesession)
        except BaseException:
            logging.getLogger().error(
                "update session [unable to read the list of session files] del fichier"
                % namefilesession
            )
            if os.path.isfile(namefilesession):
                os.remove(namefilesession)
            return False
        self.datasession = session["datasession"]
        self.timevalid = session["timevalid"]
        return True

    def removesessionfile(self):
        namefilesession = os.path.join(self.pathfile, self.sessionid)
        if os.path.isfile(namefilesession):
            os.remove(namefilesession)

    def getdatasession(self):
        return self.datasession

    def setdatasession(self, data):
        self.datasession = data
        return self.sauvesession()

    def decrementation(self):
        self.timevalid = self.timevalid - 1
        if self.timevalid > 0:
            return self.sauvesession()
        logging.getLogger().debug("call function end session")
        self.callend()
        return True

    def settimeout(self, timeminute=10):
        self.timevalid = timeminute

    def isexiste(self, sessionid):
        return sessionid == self.sessionid

    def callend(self):
        logging.getLogger().debug("function signal end")
        if self.handlefunc is not None:
            self.handlefunc(self.datasession)
        if self.eventend is not None:
            self.eventend.set()

    def __repr__(self):
        return f"<session {self.sessionid}, validate {self.timevalid}, data {self.datasession}, eventend {self.eventend}> "


class session:
    def __init__(self, typemachine=None):
        self.sessiondata = []
        if typemachine == "relayserver":
            self.dirsavesession = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "..", "sessionsrelayserver"
            )
        elif typemachine == "machine":
            self.dirsavesession = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "..", "sessionsmachine"
            )
        else:
            self.dirsavesession = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "..", "sessions"
            )
        if not os.path.exists(self.dirsavesession):
            os.makedirs(self.dirsavesession, mode=0o007)
        logging.getLogger().debug(f"Manager Session : {self.dirsavesession}")

    def clearallfilesession(self):
        listfilesession = [
            x
            for x in glob.glob(os.path.join(self.dirsavesession, "*"))
            if (os.path.isfile(x) and os.path.basename(x).startswith("command"))
        ]
        for filesession in listfilesession:
            os.remove(filesession)
        self.sessiondata = []

    def addsessiondatainfo(self, sessiondatainfo):
        if self.isexist(sessiondatainfo.sessionid):
            raise SessionAssertion
        self.sessiondata.append(sessiondatainfo)
        return sessiondatainfo

    def createsessiondatainfo(
        self, sessionid, datasession={}, timevalid=10, eventend=None
    ):
        logging.getLogger().debug(f"Creation d'une Session : {self.dirsavesession}")
        obj = sessiondatainfo(
            sessionid, datasession, timevalid, eventend, pathfile=self.dirsavesession
        )
        self.sessiondata.append(obj)
        if len(datasession) != 0:
            obj.sauvesession()
        return obj

    def removefilesessionifnotsignal(self, namefilesession):
        try:
            session = loadjsonfile(namefilesession)
        except BaseException:
            logging.getLogger().error(
                f"reading file session error : del session file : {namefilesession}"
            )
            if os.path.isfile(namefilesession):
                os.remove(namefilesession)
            return False
        if (
            "datasession" in session
            and "data" in session["datasession"]
            and "sessionreload" in session["datasession"]["data"]
            and session["datasession"]["data"]["sessionreload"] is True
        ):
            logging.getLogger().debug(
                f"Reload Session {self.dirsavesession} :  signaled reloadable"
            )
            return True
        else:
            logging.getLogger().debug(
                f"Remove Session {self.dirsavesession} :  No signaled reloadable"
            )
            os.remove(namefilesession)
            return False

    def loadsessions(self):
        try:
            listfilesession = [
                x
                for x in glob.glob(os.path.join(self.dirsavesession, "*"))
                if (os.path.isfile(x) and os.path.basename(x).startswith("command"))
            ]
        except Session as e:
            logging.getLogger().error("unable to read the list of session files")
            return False
        for filesession in listfilesession:
            if self.removefilesessionifnotsignal(filesession):
                try:
                    objsession = self.sessionfromsessiondata(
                        os.path.basename(filesession)
                    )
                    if objsession is None:
                        raise SessionkeyError
                    objsession.pathfile = self.dirsavesession
                    objsession.updatesessionfromfile()
                    logging.getLogger().debug(f"load session {objsession}")
                except SessionkeyError:
                    objsession = self.createsessiondatainfo(
                        os.path.basename(filesession)
                    )
                    objsession.updatesessionfromfile()
                    logging.getLogger().debug(f"creation sesssion {objsession}")
            else:
                logging.getLogger().debug(f"do not load session {filesession}")
        return True

    def sauvesessions(self):
        for i in self.sessiondata:
            i.sauvesession()

    def sauvesessionid(self, sessionid):
        for i in self.sessiondata:
            for i in self.sessiondata:
                if i.sessionid == sessionid:
                    i.sauvesession()
                    return i
            return None

    def __decr__(self, x):
        if not x.decrementation():
            self.clear(x.sessionid)

    def decrementesessiondatainfo(self):
        list(filter(self.__decr__, self.sessiondata))
        self.__suppsessiondatainfo__()

    def __suppsessiondatainfo__(self):
        datasessioninfo = [x for x in self.sessiondata if x.timevalid <= 0]
        self.sessiondata = [x for x in self.sessiondata if x.timevalid > 0]
        for i in datasessioninfo:
            i.removesessionfile()

    def __aff__(self, x):
        if x is not None:
            print(x)

    def __affid__(self, x):
        if x is not None:
            print(x.sessionid)

    def len(self):
        return len(self.sessiondata)

    def affiche(self):
        list(map(self.__aff__, self.sessiondata))

    def afficheid(self):
        if len(self.sessiondata) != 0:
            print("liste session existe")
            list(map(self.__affid__, self.sessiondata))

    def sessionfromsessiondata(self, sessionid):
        return next((i for i in self.sessiondata if i.sessionid == sessionid), None)

    def reactualisesession(self, sessionid, timeminute=10):
        for i in self.sessiondata:
            if i.sessionid == sessionid:
                i.settimeout(timeminute)
                break

    def clear(self, sessionid, objectxmpp=None):
        for i in range(0, self.len()):
            if sessionid == self.sessiondata[i].sessionid:
                self.sessiondata[i].callend()
                self.sessiondata[i].removesessionfile()
                self.sessiondata.remove(self.sessiondata[i])
                break
        if objectxmpp is not None:
            objectxmpp.eventmanage.clear(sessionid)

    def clearnoevent(self, sessionid):
        for i in range(0, self.len()):
            if sessionid == self.sessiondata[i].sessionid:
                self.sessiondata[i].removesessionfile()
                self.sessiondata.remove(self.sessiondata[i])
                break

    def isexist(self, sessionid):
        return any(i.sessionid == sessionid for i in self.sessiondata)

    def sessionevent(self, sessionid):
        return next(
            (
                i
                for i in self.sessiondata
                if i.sessionid == sessionid and i.eventend is not None
            ),
            None,
        )

    def sessionstop(self):
        for i in range(0, self.len()):
            self.sessiondata[i].sauvesession()
        self.sessiondata = []

    def sessionsetdata(self, sessionid, data):
        for i in self.sessiondata:
            if i.sessionid == sessionid:
                i.setdatasession(data)
