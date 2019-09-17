# -*- coding: utf-8 -*-
#
# (c) 2016 siveo, http://www.siveo.net
# plugin register machine dans presence table xmpp.
# file pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_substitutedeploy.py
#
import zlib
import base64
import traceback
import os
import sys
import urllib2
import time
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.localisation import Localisation
from lib.manageRSAsigned import MsgsignedRSA
from sleekxmpp import jid
from lib.utils import getRandomName, call_plugin
import re
from distutils.version import LooseVersion, StrictVersion
import ConfigParser

# this import will be used later
# import types

logger = logging.getLogger()

plugin = {"VERSION": "1.00", "NAME": "substitutedeploy", "TYPE": "substitute"}



def action(objectxmpp, action, sessionid, data, msg, ret, dataobj):
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s"%(plugin, msg['from']))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)

        if compteurcallplugin == 0:
            # dictionary used for deploy
            objectxmpp.machineWakeOnLan = {}
            objectxmpp.machineDeploy = {}
            read_conf_substitutedeploy(objectxmpp)
            # declartion function in object xmpp
            objectxmpp.scheduledeploy = types.MethodType(scheduledeploy,
                                                         objectxmpp)

            objectxmpp.applicationdeployjsonUuidMachineAndUuidPackage = \
                types.MethodType(applicationdeployjsonUuidMachineAndUuidPackage,
                                objectxmpp)

            objectxmpp.applicationdeployjsonuuid = types.MethodType(applicationdeployjsonuuid,
                                                                    objectxmpp)


            objectxmpp.applicationdeploymentjson = types.MethodType(applicationdeploymentjson,
                                                                    objectxmpp)

            objectxmpp.syncthingdeploy = types.MethodType(syncthingdeploy,
                                                          objectxmpp)


            objectxmpp.callpluginmasterfrommmc = types.MethodType(callpluginmasterfrommmc,
                                                          objectxmpp)

            objectxmpp.callpluginmaster = types.MethodType(callpluginmaster,
                                                          objectxmpp)

            # chedule function scheduledeploy
            objectxmpp.schedule('check_and_process_deployment',
                            TIMESCHEDULERDEPLOY,
                            objectxmpp.scheduledeploy,
                            repeat=True)


        if 'action' in data and data['action'] == 'substitutedeploy':

                for function_plugin in pluginfunction:
                    try:
                        if hasattr(objectxmpp, function_plugin):
                            getattr(objectxmpp, function_plugin)(msg, data)
                        else:
                            logger.warning("the %s plugin is not called"%function_plugin)
                            logger.warning("verify why plugging %s"\
                                " has no function %s"%(function_plugin,
                                                       function_plugin))
                    except:
                        logger.error("\n%s"%(traceback.format_exc()))


    except Exception as e:
        logger.error("machine info %s\n%s" % (str(e),traceback.format_exc()))



def scheduledeploy(self):
    """
        # Set to pause the folders already shared into the ars.
        # Clean the syncthing deployments.
        # Search all the syncthing deployment done
        # and clean into the network and the machines
    """

    # Firstly we replace the current rule by a new one.
    # 2 transfers done limit the ARS bandwidth.
    # Be aware of the new's deploy creation, its remove the limite rate.
    # TODO
    # If 1 package is in pending state, then the limit rate is removed.
    list_ars_syncthing_pause =  XmppMasterDatabase().get_ars_for_pausing_syncthing(2)
    for arssyncthing in list_ars_syncthing_pause:
        datasend = {  "action" : "deploysyncthing",
                        "sessionid" : name_random(5, "pausesyncthing"),
                        "data" : {  "subaction" : "pausefolder",
                                    "folder" : arssyncthing[2]}
                    }
        listars = arssyncthing[1].split(",")
        for arssyncthing in listars:
            self.send_message(  mto=arssyncthing,
                                mbody=json.dumps(datasend),
                                mtype='chat')
    try:
        deploys_to_clean = XmppMasterDatabase().get_syncthing_deploy_to_clean()
        if type(deploys_to_clean) is list:
            for deploydata in deploys_to_clean:
                ars = XmppMasterDatabase().get_list_ars_from_cluster(deploydata['numcluster'])
                datasend = {"action" : "deploysyncthing",
                            "sessionid" : name_random(5, "cleansyncthing"),
                            "data" : {  "subaction" : "cleandeploy",
                                        "iddeploy" : deploydata['directory_tmp'],
                                        "jidmachines" : deploydata['jidmachines'],
                                        "jidrelays" : deploydata['jidrelays'] } }
                for relay in ars:
                    print relay['jid']
                for relay in ars:
                    self.send_message(  mto=relay['jid'],
                                        mbody=json.dumps(datasend),
                                        mtype='chat')
                XmppMasterDatabase().refresh_syncthing_deploy_clean(deploydata['id'])
    except Exception:
        pass

    listobjsupp = []
    #search deploy to rumming
    resultdeploymachine, wolupdatemachine = MscDatabase().deployxmpp(800)
    for uuiddeploy in self.machineWakeOnLan:
        # not SEND WOL on presense machine
        if XmppMasterDatabase().getPresenceuuid(uuiddeploy):
            listobjsupp.append(uuiddeploy)
    for objsupp in listobjsupp:
        try:
            del self.machineWakeOnLan[uuiddeploy]
        except Exception:
            pass
    for deployobject in resultdeploymachine:
        # creation deployment
        UUID = deployobject['UUID']
        if XmppMasterDatabase().getPresenceuuid(UUID):
            # If a machine is present, add deployment in deploy list to manage.
            try:
                self.machineDeploy[UUID].append(deployobject)
            except:
                #creation list deployement
                self.machineDeploy[UUID] = []
                self.machineDeploy[UUID].append(deployobject)

    for deploy in wolupdatemachine:
        UUID = deploy['UUID']

        if UUID in self.machineWakeOnLan:
            if 'count' in self.machineWakeOnLan[UUID]:
                self.machineWakeOnLan[UUID]['count'] += 1
            else:
                self.machineWakeOnLan[UUID] = {}
                self.machineWakeOnLan[UUID]['count'] = 0
            if not 'mac' in self.machineWakeOnLan[UUID]:
                self.machineWakeOnLan[UUID]['mac'] = deploy['mac']
            if not 'commanid' in self.machineWakeOnLan[UUID]:
                self.machineWakeOnLan[UUID]['commanid'] = deploy['commandid']
        else:
            self.machineWakeOnLan[UUID] = {}
            self.machineWakeOnLan[UUID]['count'] = 0
            self.machineWakeOnLan[UUID]['commanid'] = deploy['commandid']
            self.machineWakeOnLan[UUID]['mac'] = deploy['mac']

    for uuidmachine in self.machineWakeOnLan:
        # TODO : Replace print by log
        #print self.machineWakeOnLan[uuidmachine]['count']
        if self.machineWakeOnLan[uuidmachine]['count'] < self.CYCLESCHEDULER:
            listmacadress = self.machineWakeOnLan[uuidmachine]['mac'].split("||")
            for macadress in listmacadress:
                if macadress != "":
                    logging.debug("wakeonlan machine  [Machine : %s]" % uuidmachine)
                    self.callpluginmasterfrommmc('wakeonlan', {'macadress': macadress})

    listobjsupp = []
    nbdeploy=len(self.machineDeploy)
    for deployuuid in self.machineDeploy:
        try:
            deployobject = self.machineDeploy[deployuuid].pop(0)
            listobjsupp.append(deployuuid)
            logging.debug("send deploy on machine %s package %s" %
                            (deployuuid, deployobject['pakkageid']))
            self.applicationdeployjsonUuidMachineAndUuidPackage(deployuuid,
                                                                deployobject['pakkageid'],
                                                                deployobject['commandid'],
                                                                deployobject['login'],
                                                                30,
                                                                encodebase64=False,
                                                                start_date=deployobject['start_date'],
                                                                end_date=deployobject['end_date'],
                                                                title=deployobject['title'],
                                                                macadress=deployobject['mac'],
                                                                GUID=deployobject['GUID'],
                                                                nbdeploy=nbdeploy)
        except Exception:
            listobjsupp.append(deployuuid)
    for objsupp in listobjsupp:
        try:
            del self.machineDeploy[objsupp]
        except Exception:
            pass



def applicationdeployjsonUuidMachineAndUuidPackage(self,
                                                    uuidmachine,
                                                    uuidpackage,
                                                    idcommand,
                                                    login,
                                                    time,
                                                    encodebase64=False,
                                                    start_date=None,
                                                    end_date=None,
                                                    macadress=None,
                                                    GUID=None,
                                                    title=None,
                                                    nbdeploy=-1):
    name = managepackage.getnamepackagefromuuidpackage(uuidpackage)
    if name is not None:
        return self.applicationdeployjsonuuid(str(uuidmachine),
                                                str(name),
                                                idcommand,
                                                login,
                                                time,
                                                start_date=start_date,
                                                end_date=end_date,
                                                macadress=macadress,
                                                GUID=GUID,
                                                title=title,
                                                nbdeploy=nbdeploy)
    else:
        logger.warn('%s package is not a xmpp package : (The json xmpp descriptor is missing)')
        return False

def applicationdeployjsonuuid(self,
                                uuidmachine,
                                name,
                                idcommand,
                                login,
                                time,
                                encodebase64=False,
                                uuidpackage="",
                                start_date=None,
                                end_date=None,
                                title=None,
                                macadress=None,
                                GUID=None,
                                nbdeploy=-1):

    try:
        # search group deploy and jid machine
        objmachine = XmppMasterDatabase().getGuacamoleRelayServerMachineUuid(uuidmachine)

        jidrelay = objmachine['groupdeploy']
        jidmachine = objmachine['jid']
        keysyncthing = objmachine['keysyncthing']
        if jidmachine != None and jidmachine != "" and jidrelay != None and jidrelay != "":

            return self.applicationdeploymentjson(jidrelay,
                                                    jidmachine,
                                                    idcommand,
                                                    login,
                                                    name,
                                                    time,
                                                    encodebase64=False,
                                                    uuidmachine=uuidmachine,
                                                    start_date=start_date,
                                                    end_date=end_date,
                                                    title=title,
                                                    macadress=macadress,
                                                    GUID=GUID,
                                                    keysyncthing = keysyncthing,
                                                    nbdeploy=nbdeploy)
        else:
            logger.error("deploy %s error on machine %s" % (name, uuidmachine))
            return False
    except:
        traceback.print_exc(file=sys.stdout)
        logger.error("deploy %s error on machine %s" % (name, uuidmachine))
        return False

def applicationdeploymentjson(self,
                                  jidrelay,
                                  jidmachine,
                                  idcommand,
                                  login,
                                  name,
                                  time,
                                  encodebase64=False,
                                  uuidmachine="",
                                  start_date=None,
                                  end_date=None,
                                  title=None,
                                  macadress=None,
                                  GUID=None,
                                  keysyncthing = "",
                                  nbdeploy=-1):
        """ For a deployment
        1st action: synchronizes the previous package name
        The package is already on the machine and also in relay server.
        """

        if managepackage.getversionpackagename(name) is None:
            logger.error("deploy %s error package name version missing" % (name))
            return False
        # Name the event
        dd = name_random(5, "deploy_")
        path = managepackage.getpathpackagename(name)
        if path is None:
            logger.error("package Name missing (%s)" % (name))
            return False
        descript = managepackage.loadjsonfile(os.path.join(path, 'xmppdeploy.json'))

        self.parsexmppjsonfile(os.path.join(path, 'xmppdeploy.json'))
        if descript is None:
            logger.error("deploy %s on %s  error : xmppdeploy.json missing" % (name, uuidmachine))
            return False
        objdeployadvanced = XmppMasterDatabase().datacmddeploy(idcommand)
        data = {"name": name,
                "login": login,
                "idcmd": idcommand,
                "advanced": objdeployadvanced,
                "stardate" : self.totimestamp(start_date),
                "enddate" : self.totimestamp(end_date),
                'methodetransfert': 'pushrsync',
                "path": path,
                "packagefile": os.listdir(path),
                "jidrelay": jidrelay,
                "jidmachine": jidmachine,
                "jidmaster": self.boundjid.bare,
                "iprelay":  XmppMasterDatabase().ipserverARS(jidrelay)[0],
                "ippackageserver":  XmppMasterDatabase().ippackageserver(jidrelay)[0],
                "portpackageserver":  XmppMasterDatabase().portpackageserver(jidrelay)[0],
                "ipmachine": XmppMasterDatabase().ipfromjid(jidmachine)[0],
                "ipmaster": self.config.Server,
                "Dtypequery": "TQ",
                "Devent": "DEPLOYMENT START",
                "uuid": uuidmachine,
                "descriptor": descript,
                "transfert": True,
                "nbdeploy" : nbdeploy
                }

        #TODO on verify dans la table syncthing machine
        # si il n'y a pas un partage syncthing en cour pour cette machine
        # si c'est la cas on ignore cette machine car deja en deploy.
        #res = XmppMasterDatabase().deploy_machine_partage_exist( jidmachine,
                                        #descript['info']['packageUuid'])
        #if len(res) > 0:
            #print "il existe 1 deployement de ce package [%s]"\
                #"sur la machine [%s]"%(descript['info']['packageUuid'],
                                       #jidmachine)
            #logger.debug("il existe 1 deployement de ce package [%s]"\
                #"sur la machine [%s]"%(descript['info']['packageUuid'],
                                       #jidmachine))
            #return

        # todo rattacher 1 deployement d'un package d'une machine si partage syncthing sur cluster existe deja pour d'autre machines.
        # res = XmppMasterDatabase().getnumcluster_for_ars(jidrelay)

        ###### ici on peut savoir si c'est 1 groupe et si syncthing est demande
        state = "DEPLOYMENT START"
        #data['advanced']['syncthing'] = 1
        if data['advanced']['grp'] != None and \
            'syncthing' in data['advanced'] and \
            data['advanced']['syncthing'] == 1 and \
                nbdeploy > 2:
            # deploiement avec syncthing
            # call plugin preparesyncthing on master or assesseur master
            # addition session
            # send deploy descriptor to machine
            sessionid = self.send_session_command( jidmachine,
                                                   "deploysyncthing",
                                                   data,
                                                   datasession=None,
                                                   encodebase64=False,
                                                   prefix = "command")
            #state = "DEPLOYMENT SYNCTHING"
            result = json.dumps(data, indent = 4)
        else:
            data['advanced']['syncthing'] = 0
            result = None
            sessionid = self.send_session_command(jidrelay,
                                                  "applicationdeploymentjson",
                                                  data,
                                                  datasession=None,
                                                  encodebase64=False,
                                                  prefix = "command")
        if data['advanced']['syncthing'] == 0:
            msglog = "Start deploy on machine %s" % jidmachine
        else:
            msglog = "Start deploy Syncthing on machine %s" % jidmachine
        self.xmpplog(msglog,
                     type='deploy',
                     sessionname=sessionid,
                     priority=-1,
                     action="",
                     who="",
                     how="",
                     why=self.boundjid.bare,
                     module="Deployment | Start | Creation",
                     date=None,
                     fromuser=data['login'],
                     touser="")

        XmppMasterDatabase().adddeploy(idcommand,
                                       jidmachine,
                                       jidrelay,
                                       jidmachine,
                                       uuidmachine,
                                       descript['info']['name'],
                                       state,
                                       sessionid,
                                       user="",
                                       login=login,
                                       title=title,
                                       group_uuid=GUID,
                                       startcmd=start_date,
                                       endcmd=end_date,
                                       macadress=macadress,
                                       result = result,
                                       syncthing = data['advanced']['syncthing']
                                       )
        if data['advanced']['syncthing'] == 0:
            XmppMasterDatabase().addcluster_resources(jidmachine,
                                                    jidrelay,
                                                    jidmachine,
                                                    sessionid,
                                                    login=login,
                                                    startcmd = start_date,
                                                    endcmd = end_date
                                                    )
        self.syncthingdeploy()
        return sessionid
    
def syncthingdeploy(self):
    #nanlyse la table deploy et recupere les deployement syncthing.
    iddeploylist = XmppMasterDatabase().deploysyncthingxmpp()
    if len(iddeploylist)!= 0:
        for iddeploy in iddeploylist:
            # les tables sont create
            # maintenant on appelle le plugin master de syncthing
            data = { "subaction" : "initialisation",
                        "iddeploy" : iddeploy }
            self.callpluginmasterfrommmc("deploysyncthing",
                                            data,
                                            sessionid = name_randomplus(25,
                                            pref="deploysyncthing"))

def callpluginmasterfrommmc(self, plugin, data, sessionid=None):
    if sessionid == None:
        sessionid = name_random(5, plugin)
    msg = {}
    msg['from'] = self.boundjid.bare
    msg['body'] = json.dumps({'action': plugin,
                                'ret': 0,
                                'sessionid': sessionid,
                                'data': data})
    self.callpluginmaster(msg)

def callpluginmaster(self, msg):
    try:
        dataobj = json.loads(msg['body'])
        if dataobj.has_key('action') and dataobj['action'] != "" and dataobj.has_key('data'):
            if dataobj.has_key('base64') and \
                ((isinstance(dataobj['base64'], bool) and dataobj['base64'] == True) or
                    (isinstance(dataobj['base64'], str) and dataobj['base64'].lower() == 'true')):
                mydata = json.loads(base64.b64decode(dataobj['data']))
            else:
                mydata = dataobj['data']
            if not dataobj.has_key('sessionid'):
                dataobj['sessionid'] = "absent"
            if not 'ret' in dataobj:
                dataobj['ret'] = 0
            try:
                logging.debug("Calling plugin %s from  %s" % (dataobj['action'], msg['from']))
                msg['body'] = dataobj
                del dataobj['data']
                call_plugin(dataobj['action'],
                            self,
                            dataobj['action'],
                            dataobj['sessionid'],
                            mydata,
                            msg,
                            dataobj['ret'],
                            dataobj
                            )
            except TypeError:
                logging.error("TypeError: executing plugin %s %s" %
                                (dataobj['action'], sys.exc_info()[0]))
                traceback.print_exc(file=sys.stdout)

            except Exception as e:
                logging.error("Executing plugin (%s) %s %s" % (msg['from'], dataobj['action'], str(e)))
                traceback.print_exc(file=sys.stdout)

    except Exception as e:
        logging.error("Message structure %s   %s " % (msg, str(e)))
        traceback.print_exc(file=sys.stdout)

def read_conf_substitutedeploy(objectxmpp):
    logger.debug("Initialisation plugin :% s "%plugin["NAME"])
    namefichierconf = plugin['NAME'] + ".ini"
    pathfileconf = os.path.join( objectxmpp.config.pathdirconffile, namefichierconf )
    if not os.path.isfile(pathfileconf):
        pluginlistunregistered =""
        objectxmpp.TIMESCHEDULERDEPLOY = 30
    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathfileconf)
        if Config.has_option("parameters", "pluginlistunregistered"):
            pluginlistunregistered = Config.get('parameters', 'pluginlistunregistered')
        else:
            pluginlistunregistered = ""# list plugin  ex:   pluginlistunregistered = "dede, dede1, dede2"

        if Config.has_option("parameters", "TIMESCHEDULERDEPLOY"):
            objectxmpp.TIMESCHEDULERDEPLOY =  Config.getint('parameters', 'TIMESCHEDULERDEPLOY')
        else:
            objectxmpp.TIMESCHEDULERDEPLOY = 30
    objectxmpp.pluginlistunregistered = [x.strip() for x in pluginlistunregistered.split(',')]
