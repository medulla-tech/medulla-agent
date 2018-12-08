# -*- coding: utf-8; -*-
#
# (c) 2016 siveo, http://www.siveo.net
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
# file pulse_xmpp_agent/lib/managesession.py
#
import glob
import os
import json
import logging
from utils import decode_strconsole, loadjsonfile

class Session(Exception):
    pass


class SessionAssertion(Session, AssertionError):
    pass


class Sessionpathsauvemissing(Session, Exception):
    pass


class SessionkeyError(Session, KeyError):
    pass


class sessiondatainfo:

    def __init__(self, sessionid, datasession=None, timevalid=10,
                 eventend=None, handlefunc=None, pathfile=None):
        if datasession is None:
            datasession = {}
        self.sessionid = sessionid
        self.timevalid = timevalid
        self.datasession = datasession
        self.eventend = eventend
        self.handlefunc = handlefunc
        self.pathfile = pathfile
        if pathfile == None:
            raise Sessionpathsauvemissing
        logging.getLogger().debug("Creation manager session")

    def jsonsession(self):
        session = {
            'sessionid': self.sessionid,
            'timevalid': self.timevalid,
            'datasession': self.datasession}
        return json.dumps(session)

    def sauvesession(self):
        namefilesession = os.path.join(self.pathfile, self.sessionid)
        logging.getLogger().debug("save session in file %s" % namefilesession)
        session = {
            'sessionid': self.sessionid,
            'timevalid': self.timevalid,
            'datasession': self.datasession}
        # write session.
        try:
            with open(namefilesession, 'w') as f:
                json.dump(session, f, indent=4)
            return True
        except Exception as e:
            logging.getLogger().error("impossible ecrire la session %s : %s" %(namefilesession, str(e)))
            logging.getLogger().error("del fille session")
            if os.path.isfile(namefilesession):
                logging.getLogger().error("fille session %s does not exist"%namefilesession)
                os.remove(namefilesession)
            return False
        return True

    def updatesessionfromfile(self):
        namefilesession = os.path.join(self.pathfile, self.sessionid)
        logging.getLogger().debug("UPDATE SESSION")
        try:
            session = loadjsonfile(namefilesession)
        except :
            logging.getLogger().error("update session [unable to read the list of session files] del fichier" %namefilesession)
            if os.path.isfile(namefilesession):
                os.remove(namefilesession)
            return False
        self.datasession = session['datasession']
        self.timevalid = session['timevalid']
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
        if self.handlefunc != None:
            self.handlefunc(self.datasession)
        if self.eventend != None:
            self.eventend.set()

    def __repr__(self):
        return "<session %s, validate %s, data %s, eventend %s> " % (
            self.sessionid, self.timevalid, self.datasession, self.eventend)


class session:
    def __init__(self, typemachine=None):
        self.sessiondata = []
        if(typemachine == "relayserver"):
            self.dirsavesession = os.path.join(
                os.path.dirname(
                    os.path.realpath(__file__)),
                "..",
                "sessionsrelayserver")
        elif typemachine == "machine":
            self.dirsavesession = os.path.join(os.path.dirname(
                os.path.realpath(__file__)), "..", "sessionsmachine")
        else:
            self.dirsavesession = os.path.join(os.path.dirname(
                os.path.realpath(__file__)), "..", "sessions")
        if not os.path.exists(self.dirsavesession):
            os.makedirs(self.dirsavesession, mode=0o007)
        logging.getLogger().debug("Manager Session : %s" % self.dirsavesession)

    def clearallfilesession(self):
        listfilesession = [
            x for x in glob.glob(
                os.path.join(
                    self.dirsavesession,
                    "*")) if (
                os.path.isfile(x) and os.path.basename(x).startswith('command'))]
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
            self, sessionid, datasession={}, timevalid=10, eventend=None):
        logging.getLogger().debug(
            "Creation d'une Session : %s" %
            self.dirsavesession)
        obj = sessiondatainfo(
            sessionid,
            datasession,
            timevalid,
            eventend,
            pathfile=self.dirsavesession)
        self.sessiondata.append(obj)
        if len(datasession) != 0:
            obj.sauvesession()
        return obj

    def removefilesessionifnotsignal(self, namefilesession):
        try:
            session = loadjsonfile(namefilesession)
        except :
            logging.getLogger().error("reading file session error : del session file : %s" %namefilesession)
            if os.path.isfile(namefilesession):
                os.remove(namefilesession)
            return False
        if 'datasession' in session and 'data' in session['datasession'] and 'sessionreload' in session[
                'datasession']['data'] and session['datasession']['data']['sessionreload'] == True:
            logging.getLogger().debug(
                "Reload Session %s :  signaled reloadable" %
                self.dirsavesession)
            return True
        else:
            logging.getLogger().debug(
                "Remove Session %s :  No signaled reloadable" %
                self.dirsavesession)
            os.remove(namefilesession)
            return False

    def loadsessions(self):
        try :
            listfilesession = [
                x for x in glob.glob(
                    os.path.join(
                        self.dirsavesession,
                        "*")) if (
                    os.path.isfile(x) and os.path.basename(x).startswith('command'))]
        except Session as e:
            logging.getLogger().error("unable to read the list of session files")
            return False
        for filesession in listfilesession:
            if self.removefilesessionifnotsignal(filesession):
                try:
                    objsession = self.sessionfromsessiondata(
                        os.path.basename(filesession))
                    if objsession == None:
                        raise SessionkeyError
                    objsession.pathfile = self.dirsavesession
                    objsession.updatesessionfromfile()
                    logging.getLogger().debug("load session %s" % objsession)
                except SessionkeyError:
                    objsession = self.createsessiondatainfo(
                        os.path.basename(filesession))
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
            self.clear(sessionid)

    def decrementesessiondatainfo(self):
        filter(self.__decr__, self.sessiondata)
        self.__suppsessiondatainfo__()

    def __suppsessiondatainfo__(self):
        datasessioninfo = [x for x in self.sessiondata if x.timevalid <= 0]
        self.sessiondata = [x for x in self.sessiondata if x.timevalid > 0]
        for i in datasessioninfo:
            i.removesessionfile()

    def __aff__(self, x):
        if x != None:
            print x

    def __affid__(self, x):
        if x != None:
            print x.sessionid

    def len(self):
        return len(self.sessiondata)

    def affiche(self):
        map(self.__aff__, self.sessiondata)

    def afficheid(self):
        if len(self.sessiondata) != 0:
            print "liste session existe"
            map(self.__affid__, self.sessiondata)

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
        if objectxmpp != None:
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
            if i.sessionid == sessionid and i.eventend != None:
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
