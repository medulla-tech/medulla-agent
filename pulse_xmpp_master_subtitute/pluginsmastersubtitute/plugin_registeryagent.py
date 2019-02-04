# -*- coding: utf-8 -*-
#
# (c) 2016 siveo, http://www.siveo.net
# plugin register machine dans presence table xmpp.
# file pulse_xmpp_master_subtitute/pluginsmastersubtitute/plugin_registeryagent.py
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
from lib.utils import getRandomName

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "registeryagent", "TYPE": "subtitute"}


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s"%(plugin, msg['from']))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s"%action)
        if 'action' in data and data['action'] == 'infomachine':
            logger.debug(
                "** Processing machine %s that sends this information (nini inventory)" % msg['from'].bare)

            if XmppMasterDatabase().getPresencejid(msg['from'].bare):
                logger.debug("Machine %s already exists in base" % msg['from'].bare)
                return

            if XmppMasterDatabase().getPresencejiduser(msg['from'].user):
                logger.debug("Machine idem jid, domain change %s" % msg['from'].bare)
                # The registration of the machine in database must be deleted, so it is updated.
                XmppMasterDatabase().delPresenceMachinebyjiduser(msg['from'].user)

            """ Check machine information from agent """
            logger.debug(
                "** Processing and check machine information from agent and the registry into database.")
            info = json.loads(base64.b64decode(data['completedatamachine']))
            if data['ippublic'] is not None and data['ippublic'] != "":
                data['localisationinfo'] = Localisation().geodataip(data['ippublic'])
            else:
                data['localisationinfo'] = {}
            data['information'] = info

            if data['adorgbymachine'] is not None and data['adorgbymachine'] != "":
                try:
                    data['adorgbymachine'] = base64.b64decode(data['adorgbymachine'])
                except TypeError:
                    pass
            if data['adorgbyuser'] is not None and data['adorgbyuser'] != "":
                try:
                    data['adorgbyuser'] = base64.b64decode(data['adorgbyuser'])
                except TypeError:
                    pass

            publickeybase64 = info['publickey']
            is_masterpublickey = info['is_masterpublickey']
            del info['publickey']
            del info['is_masterpublickey']
            RSA = MsgsignedRSA("master")
            if not is_masterpublickey:
                # Send public key if the machine agent does not have one
                datasend = {
                    "action": "installkeymaster",
                    "keypublicbase64": RSA.loadkeypublictobase64(),
                    'ret': 0,
                    'sessionid': getRandomName(5, "publickeymaster"),
                }
                xmppobject.send_message(mto=msg['from'],
                                    mbody=json.dumps(datasend),
                                    mtype='chat')
            # ##################################
            logger.debug("** display data")
            ###self.displayData(data)
            longitude = ""
            latitude = ""
            city = ""
            region_name = ""
            time_zone = ""
            longitude = ""
            latitude = ""
            postal_code = ""
            country_code = ""
            country_name = ""
            if data['localisationinfo'] is not None and len(data['localisationinfo']) > 0:
                longitude = str(data['localisationinfo']['longitude'])
                latitude = str(data['localisationinfo']['latitude'])
                region_name = str(data['localisationinfo']['region_name'])
                time_zone = str(data['localisationinfo']['time_zone'])
                postal_code = str(data['localisationinfo']['postal_code'])
                country_code = str(data['localisationinfo']['country_code'])
                country_name = str(data['localisationinfo']['country_name'])
                city = str(data['localisationinfo']['city'])
            try:
                # Assignment of the user system, if user absent.
                if 'users' in data['information'] and len(data['information']['users']) == 0:
                    data['information']['users'] = "system"

                if 'users' in data['information'] and len(data['information']['users']) > 0:
                    logger.debug("** addition user %s in base" %
                                    data['information']['users'][0])
                    logger.info("add user : %s for machine : %s country_name : %s" % (data['information']['users'][0],
                                                                                        data['information']['info']['hostname'],
                                                                                        country_name))
                    useradd = XmppMasterDatabase().adduser(data['information']['users'][0],
                                                            data['information']['info']['hostname'],
                                                            city,
                                                            region_name,
                                                            time_zone,
                                                            longitude,
                                                            latitude,
                                                            postal_code,
                                                            country_code,
                                                            country_name)
                    try:
                        useradd = useradd[0]
                    except TypeError:
                        pass
            except Exception:
                logger.error("** not user, inscription impossible of %s" % msg['from'].bare)
                return

            # Add relayserver or update status in database
            logger.debug("** Add relayserver or update status in database %s" %
                            msg['from'].bare)
            if data['agenttype'] == "relayserver":
                data["adorgbyuser"] = ""
                data["adorgbymachine"] = ""
                data["kiosk_presence"] = ""

                if 'moderelayserver' in data:
                    moderelayserver = data['moderelayserver']
                else:
                    moderelayserver = "static"
                XmppMasterDatabase().addServerRelay(data['baseurlguacamole'],
                                                    data['subnetxmpp'],
                                                    data['information']['info']['hostname'],
                                                    data['deployment'],
                                                    data['xmppip'],
                                                    data['ipconnection'],
                                                    data['portconnection'],
                                                    data['portxmpp'],
                                                    data['xmppmask'],
                                                    data['from'],
                                                    longitude,
                                                    latitude,
                                                    True,
                                                    data['classutil'],
                                                    data['packageserver']['public_ip'],
                                                    data['packageserver']['port'],
                                                    moderelayserver=moderelayserver
                                                    )
                # Recover list of cluster ARS
                listrelayserver = XmppMasterDatabase(
                ).getRelayServerofclusterFromjidars(str(data['from']))
                cluster = {'action': "cluster",
                            'sessionid': getRandomName(5, "cluster"),
                            'data': {'subaction': 'initclusterlist',
                                        'data': listrelayserver
                                    }
                            }

                # All relays server in the cluster are notified.
                for ARScluster in listrelayserver:
                    xmppobject.send_message(mto=ARScluster,
                                        mbody=json.dumps(cluster),
                                        mtype='chat')
            logger.debug("** Add machine in database")
            # Add machine
            ippublic = None
            if "ippublic" in data:
                ippublic = data['ippublic']
            if ippublic == None:
                ippublic = data['xmppip']
            kiosk_presence = ""
            if 'kiosk_presence' in data and data['kiosk_presence'] != "":
                kiosk_presence = data['kiosk_presence']
            else:
                kiosk_presence = "False"
            if not 'lastusersession' in data:
                data['lastusersession'] = ""
            idmachine = XmppMasterDatabase().addPresenceMachine(data['from'],
                                                                data['platform'],
                                                                data['information']['info']['hostname'],
                                                                data['information']['info']['hardtype'],
                                                                None,
                                                                data['xmppip'],
                                                                data['subnetxmpp'],
                                                                data['xmppmacaddress'],
                                                                data['agenttype'],
                                                                classutil=data['classutil'],
                                                                urlguacamole=data['baseurlguacamole'],
                                                                groupdeploy=data['deployment'],
                                                                objkeypublic=publickeybase64,
                                                                ippublic=ippublic,
                                                                ad_ou_user=data['adorgbyuser'],
                                                                ad_ou_machine=data['adorgbymachine'],
                                                                kiosk_presence=kiosk_presence,
                                                                lastuser=data['lastusersession']
                                                                )
            if idmachine != -1:
                if useradd != -1:
                    XmppMasterDatabase().hasmachineusers(useradd, idmachine)
                else:
                    logger.error("** Not user found for the machine")
                    return
                for i in data['information']["listipinfo"]:
                    try:
                        broadcast = i['broadcast']
                    except:
                        broadcast = ''
                    logger.debug("** Add interface %s in database for machine %s" %
                                    (str(i['macaddress']), msg['from'].bare))
                    XmppMasterDatabase().addPresenceNetwork(
                        i['macaddress'], i['ipaddress'], broadcast, i['gateway'], i['mask'], i['macnotshortened'], idmachine)
                if data['agenttype'] != "relayserver":
                    # Update the machine uuid : for consistency with inventory
                    # call Guacamole config
                    # or add inventory
                    #logger.debug(
                        #"** Update the machine uuid : for consistency with inventory\ncall Guacamole config\nor add inventory")
                    result = XmppMasterDatabase().listMacAdressforMachine(idmachine)
                    results = result[0].split(",")

                    logger.debug("List mac adress for machine   %s" % results)
                    uuid = ''
                    for t in results:
                        computer = getComputerByMac(t)
                        if computer != None:
                            jidrs = str(jid.JID(data['deployment']).user)
                            jidm = jid.JID(data['from']).domain
                            jidrs = "%s@%s" % (jidrs, jidm)
                            uuid = 'UUID' + str(computer.id)
                            logger.debug("** Update uuid %s for machine %s " %
                                            (uuid, msg['from'].bare))
                            XmppMasterDatabase().updateMachineidinventory(uuid, idmachine)
                            if 'countstart' in data and data['countstart'] == 1:
                                logger.debug("** Call inventory on PXE machine")
                                callinventory(xmppobject, data['from'])
                                return
                            osmachine = Glpi().getComputersOS(str(computer.id))
                            #osmachine = ComputerManager().getComputersOS(str(computer.id))
                            if "Unknown operating system (PXE" in osmachine[0]['OSName']:
                                logger.debug("** Call inventory on PXE machine")
                                callinventory(xmppobject, data['from'])
                                return
                            if "kiosk" in xmppobject.listmodulemmc and kiosk_presence:
                                ## send a data message to kiosk when an inventory is registered
                                handlerkioskpresence( xmppobject,
                                                    data['from'],
                                                    idmachine,
                                                    data['platform'],
                                                    data['information']['info']['hostname'],
                                                    uuid,
                                                    data['agenttype'],
                                                    classutil=data['classutil'],
                                                    fromplugin = True )
                            XmppMasterDatabase().setlogxmpp("Remote Service <b>%s</b> : for [machine : %s][RS : %s]" % (data['remoteservice'],
                                                                                                                        data['information']['info']['hostname'],
                                                                                                                        jidrs,),
                                                            "Master",
                                                            "",
                                                            0,
                                                            data['from'],
                                                            'auto',
                                                            '',
                                                            'Remote_desktop | Guacamole | Service | Auto',
                                                            '',
                                                            '',
                                                            "Master")
                            callInstallConfGuacamole(xmppobject,   
                                                     jidrs, 
                                                     {  'hostname': data['information']['info']['hostname'],
                                                        'machine_ip': data['xmppip'],
                                                        'uuid': str(computer.id),
                                                        'remoteservice': data['remoteservice'],
                                                        'platform' : data['platform'],
                                                        'os' : data['information']['info']['os']})
                            break

                        else:
                            logger.debug("No computer found")
                            pass
                    else:
                        # Register machine at inventory creation
                        logger.debug("** Call inventory on %s" % msg['from'].bare)
                        XmppMasterDatabase().setlogxmpp("Master ask inventory for registration",
                                                        "Master",
                                                        "",
                                                        0,
                                                        data['from'],
                                                        'auto',
                                                        '',
                                                        'QuickAction|Inventory|Inventory requested',
                                                        '',
                                                        '',
                                                        "Master")
                        callinventory(xmppobject, data['from'])
            else:
                logger.error("** Database registration error")
                return

            pluginfunction = ['plugin_autoupdate', 
                              'pulgin_loadpluginlistversion', 
                              'plugin_loadpluginschedulerlistversion', 
                              'plugin_loadpluginschedulerlistversion',
                              'plugin_showregistration']

            for function_plugin in pluginfunction:
                try:
                    if hasattr(xmppobject, function_plugin):
                        if function_plugin == 'plugin_showregistration':
                            if logger.level == logging.DEBUG:
                                getattr(xmppobject, function_plugin)(msg, data)
                    else:
                        getattr(xmppobject, function_plugin)(msg, data)
                except:
                    logger.error("\n%s"%(traceback.format_exc()))

            ########################################
            #### rmote update plugin
            ########################################
            #try:
                #xmppobject.plugin_autoupdate(msg, data)
            #except AttributeError:
                #pass
            ########################################
            #### rmote update plugin
            ########################################

            ########################################
            #### install plugin
            ########################################
            #restartAgent = False
            #try:
                #xmppobject.pulgin_loadpluginlistversion(msg, data)
            #except AttributeError:
                #pass
            ########################################
            #### install plugin
            ########################################

            ########################################
            #### install plugin scheduled
            ########################################
            #try:
                #xmppobject.plugin_loadpluginschedulerlistversion(msg, data)
            #except AttributeError:
                #pass
            ########################################
            #### install plugin scheduled
            ########################################

            ########################################
            #### install plugin scheduled
            ########################################
            #try:
                #if hasattr(xmppobject, "plugin_showregistration"):
                    #xmppobject.plugin_loadpluginschedulerlistversion(msg, data)
            #except:
                #logger.error("\n%s"%(traceback.format_exc()))
            ########################################
            #### install plugin scheduled
            ########################################

            ########################################
            #### showregistration
            ########################################
            #try:
                #if hasattr(xmppobject, "plugin_showregistration"):
                    #del data['completedatamachine']
                    #del data['plugin']
                    #del data['pluginscheduled']
                    #xmppobject.plugin_showregistration(msg, data)
            #except:
                #logger.error("\n%s"%(traceback.format_exc()))
                ##logger.debug( "Unexpected error plugin_showregistration: %s"%sys.exc_info()[0])
            #######################################
            ### showregistration
            #######################################
    except Exception as e:
        logger.error("machine info %s\n%s" % (str(e),traceback.format_exc()))

def getComputerByMac( mac):
    ret = Glpi().getMachineByMacAddress('imaging_module', mac)
    if type(ret) == list:
        if len(ret) != 0:
            return ret[0]
        else:
            return None
    return ret

def callInstallConfGuacamole(xmppobject, torelayserver, data):
    try:
        body = {'action': 'guacamoleconf',
                'sessionid': getRandomName(5, "guacamoleconf"),
                'data': data}
        xmppobject.send_message(mto=torelayserver,
                            mbody=json.dumps(body),
                            mtype='chat')
    except:
        logger.error("\n%s"%(traceback.format_exc()))

def callinventory(xmppobject,  to):
    try:
        body = {'action': 'inventory',
                'sessionid': getRandomName(5, "inventory"),
                'data': {}}
        xmppobject.send_message(mto=to,
                            mbody=json.dumps(body),
                            mtype='chat')
    except:
        logger.error("\n%s"%(traceback.format_exc()))


def data_struct_message(action, data = {}, ret=0, base64 = False, sessionid = None):
    if sessionid == None or sessionid == "" or not isinstance(sessionid, basestring):
        sessionid = action.strip().replace(" ", "")
    return { 'action' : action,
             'data' : data,
             'ret' : 0, 
             "base64" : False,
             "sessionid" : getRandomName(4,sessionid) }

def handlerkioskpresence(xmppobject, jid, id, os, hostname, uuid_inventorymachine, agenttype, classutil, fromplugin = False):
    """
    This function launch the kiosk actions when a prensence machine is active
    """
    logger.debug("kiosk handled")
    # print jid, id, os, hostname, uuid_inventorymachine, agenttype, classutil
    # get the profiles from the table machine.
    machine = XmppMasterDatabase().getMachinefromjid(jid)
    structuredatakiosk = get_packages_for_machine(machine)
    datas = { 'subaction':'initialisation_kiosk',
              'data' : structuredatakiosk }
    message_to_machine = data_struct_message("kiosk", 
                                             data = datas, 
                                             ret = 0, 
                                             base64 = False, 
                                             sessionid = getRandomName(6, "initialisation_kiosk"))
    xmppobject.send_message(mto = jid,
                            mbody = json.dumps(message_to_machine),
                            mtype = 'chat')
    return datas

def get_packages_for_machine(machine):
    """Get a list of the packages for the concerned machine.
    Param:
        machine : tuple of the machine datas
    Returns:
        list of the packages"""
    OUmachine = [machine['ad_ou_machine'].replace("\n",'').replace("\r",'').replace('@@','/')]
    OUuser = [machine['ad_ou_user'].replace("\n", '').replace("\r", '').replace('@@','/')]

    OU = list(set(OUmachine + OUuser))

    # search packages for the applied profiles
    list_profile_packages =  KioskDatabase().get_profile_list_for_OUList(OU)
    if list_profile_packages is None:
        #TODO
        # linux and mac os does not have an Organization Unit.
        # For mac os and linux, profile association will be done on the login name.
        return
    list_software_glpi = []
    softwareonmachine = Glpi().getLastMachineInventoryPart(machine['uuid_inventorymachine'],
                                                           'Softwares', 0, -1, '',
                                                           {'hide_win_updates': True, 'history_delta': ''})
    for x in softwareonmachine:
        list_software_glpi.append([x[0][1],x[1][1], x[2][1]])
    #print list_software_glpi # ordre information [["Vendor","Name","Version"],]
    structuredatakiosk = []

    #Create structuredatakiosk for initialization
    for packageprofile in list_profile_packages:
        structuredatakiosk.append( __search_software_in_glpi(list_software_glpi,
        packageprofile, structuredatakiosk))
    #logger.debug("initialisation kiosk %s on machine %s"%(structuredatakiosk, machine['hostname']))
    logger.debug("* initialisation kiosk on machine %s"%(machine['hostname']))
    return structuredatakiosk

