# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import glob
import os
import json
import logging
from lib.utils import loadjsonfile
from os import listdir
import time
import traceback


def clean_session(folder_session):
    tt = time.time()
    fichiers = [
        os.path.join(folder_session, f)
        for f in listdir(folder_session)
        if len(f) == 25 and os.path.isfile(os.path.join(folder_session, f))
    ]
    for fic in fichiers:
        creation = os.path.getmtime(fic)
        try:
            with open(fic) as json_data:
                data_dict = json.load(json_data)
            if (data_dict["timevalid"] + creation) < tt:
                # delete file
                # print "delete %s"%fic
                os.remove(fic)
            else:
                pass
                # print "session  %s non terminer"%fic
        except BaseException:
            os.remove(fic)
            errorstr = "%s" % traceback.format_exc()


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
        It saves the file in the python pulse_xmpp_master_substitute folder.
        Return:
            It returns True if the file is well created.
            False, otherwise
        """
        namefilesession = os.path.join(self.pathfile, self.sessionid)
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
                "We encountered an issue while creating the session %s"
                % namefilesession
            )
            logging.getLogger().error("The error is %s" % str(e))
            if os.path.isfile(namefilesession):
                os.remove(namefilesession)
            return False
        return True

    def updatesessionfromfile(self):
        namefilesession = os.path.join(self.pathfile, self.sessionid)
        logging.getLogger().debug("UPDATE SESSION")
        try:
            session = loadjsonfile(namefilesession)
        except Exception:
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
        if self.timevalid <= 0:
            logging.getLogger().debug("call function end session")
            self.callend()
            return True
        else:
            return self.sauvesession()

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
        return "<session %s, validate %s, data %s, eventend %s> " % (
            self.sessionid,
            self.timevalid,
            self.datasession,
            self.eventend,
        )


class session:
    def __init__(self, typemachine=None):
        self.sessiondata = []
        self.sessiondata = []
        if typemachine is None:
            typemachine = "sessions"
        self.dirsavesession = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "..", str(typemachine)
        )
        if not os.path.exists(self.dirsavesession):
            os.makedirs(self.dirsavesession, mode=0o007)
        logging.getLogger().debug("Manager Session : %s" % self.dirsavesession)

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
        else:
            self.sessiondata.append(sessiondatainfo)
            return sessiondatainfo

    def createsessiondatainfo(
        self, sessionid, datasession={}, timevalid=10, eventend=None
    ):
        logging.getLogger().debug("Creation d'une Session : %s" % self.dirsavesession)
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
        except Exception:
            logging.getLogger().error(
                "reading file session error : del session file : %s" % namefilesession
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
                "Reload Session %s :  signaled reloadable" % self.dirsavesession
            )
            return True
        else:
            logging.getLogger().debug(
                "Remove Session %s :  No signaled reloadable" % self.dirsavesession
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
                    logging.getLogger().debug("load session %s" % objsession)
                except SessionkeyError:
                    objsession = self.createsessiondatainfo(
                        os.path.basename(filesession)
                    )
                    objsession.updatesessionfromfile()
                    logging.getLogger().debug("creation sesssion %s" % objsession)
            else:
                logging.getLogger().debug("do not load session %s" % filesession)
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
        for i in self.sessiondata:
            if i.sessionid == sessionid:
                return i
        return None

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
        for i in self.sessiondata:
            if i.sessionid == sessionid:
                return True
        return False

    def sessionevent(self, sessionid):
        for i in self.sessiondata:
            if i.sessionid == sessionid and i.eventend is not None:
                return i
        return None

    def sessionstop(self):
        for i in range(0, self.len()):
            self.sessiondata[i].sauvesession()
        self.sessiondata = []

    def sessionsetdata(self, sessionid, data):
        for i in self.sessiondata:
            if i.sessionid == sessionid:
                i.setdatasession(data)

    def sessiongetdata(self, sessionid):
        for i in self.sessiondata:
            if i.sessionid == sessionid:
                return i.getdatasession()
        return None
