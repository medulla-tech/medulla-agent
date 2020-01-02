# -*- coding: utf-8 -*-
#
# (c) 2016 siveo, http://www.siveo.net
# plugin register machine dans presence table xmpp.
# file pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_registeryagent.py
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
import re
from distutils.version import LooseVersion, StrictVersion
import ConfigParser

# this import will be used later
# import types

logger = logging.getLogger()

plugin = {"VERSION": "1.02", "NAME": "registeryagent", "TYPE": "substitute"}

# function comment for next feature
# this functions will be used later
# def function_dynamique_declaration_plugin(xmppobject):
     #xmppobject.changestatusin_plugin = types.MethodType(changestatusin_plugin, xmppobject)

# def changestatusin_plugin(self, msg_changed_status):
     #logger.debug("chang status for %s"%msg_changed_status['from'])
     #pass

def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s"%(plugin, msg['from']))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s"%action)

        if compteurcallplugin == 0:
            read_conf_remote_registeryagent(xmppobject)
            #return
            #function comment for next feature
            # this functions will be used later
            ##add function for event change staus des autre agent
            #function_dynamique_declaration_plugin(xmppobject)
            ## intercepte event change status call function
            #xmppobject.add_event_handler('changed_status', xmppobject.changestatusin_plugin)

        if 'action' in data and data['action'] == 'infomachine':
            logger.debug(
                "** Processing machine %s that sends this"\
                    " information (nini inventory)" % msg['from'].bare)
            if 'completedatamachine' in data:
                info = json.loads(base64.b64decode(data['completedatamachine']))
                data['information'] = info


            machine = XmppMasterDatabase().getMachinefromjid(data['from'])
            if len(machine) != 0:
                # on regarde si coherence avec table network.
                try:
                    result = XmppMasterDatabase().listMacAdressforMachine(machine['id'])
                    if result[0] is None:
                        raise
                except Exception:
                    # incoherence entre machine et network
                    # on supprime la machine
                    # la machine est reincrite
                    logger.warning("machine %s : incoherence entre table "\
                        "machine et network."%data['from'])

                    if data['agenttype'] != "relayserver":
                        machine['enabled'] = 0
                        logger.warning("reincription complete de la machine")
                    else:
                        logger.warning("you must verify cohérence for ARS")

                if machine['enabled'] == 1:
                    logger.debug("Machine %s already exists in base" % msg['from'].bare)
                    pluginfunction=[str("plugin_%s"%x) for x in xmppobject.pluginlistregistered]
                    logger.debug("call plugin  for the present machine.")
                    for function_plugin in pluginfunction:
                        try:
                            if hasattr(xmppobject, function_plugin):
                                if function_plugin == 'plugin_showregistration':
                                    if logger.level == logging.DEBUG:
                                        logger.debug("call plugin %s"%function_plugin)
                                        getattr(xmppobject, function_plugin)(msg, data)
                                else:
                                    logger.debug("call plugin %s"%function_plugin)
                                    getattr(xmppobject, function_plugin)(msg, data)
                            else:
                                logger.warning("the %s plugin is not called"%function_plugin)
                                logger.warning("verify why plugging %s"\
                                    " has no function %s"%(function_plugin,
                                                        function_plugin))
                        except Exception:
                            logger.error("\n%s"%(traceback.format_exc()))

                    logger.debug("=============")
                    logger.debug("=============")
                    logger.debug("Case 1 : The machine %s already exists : "%str(msg['from']))
                    logger.debug("Update it's uuid_inventory_machine")
                    logger.debug("=============")
                    logger.debug("=============")
                    # on regarde si le UUID associe a hostname machine correspond au hostname dans glpi.
                    if xmppobject.check_uuidinventory and \
                        'uuid_inventorymachine' in machine and \
                            machine['uuid_inventorymachine'] is not None:
                        hostname = None
                        try:
                            re = Glpi().getLastMachineInventoryFull(machine['uuid_inventorymachine'])
                            for t in re:
                                if t[0] == 'name':
                                    hostname = t[1]
                                    break
                            if hostname and "information" in data and \
                                "info" in data["information"] and \
                                    "hostname" in  data["information"]["info"] and \
                                        hostname != data["information"]["info"]["hostname"]:
                                machine['uuid_inventorymachine'] = None
                        except Exception:
                            machine['uuid_inventorymachine'] = None
                        if machine['uuid_inventorymachine'] is None:
                            logger.warning("When there is an incoherence between xmpp and glpi's uuid, we restore the uuid from glpi")

                    if 'uuid_inventorymachine' not in machine or \
                        machine['uuid_inventorymachine'] is None or \
                        not machine['uuid_inventorymachine']:
                        if data['agenttype'] != "relayserver":
                            results = result[0].split(",")
                            nbelt = len (results)
                            results=set(results)
                            nbelt1 = len(results)
                            if nbelt != nbelt1:
                                logger.warning("%s duplicate in the network table "\
                                    "for machine [%s] id %s"%(nbelt-nbelt1, data['from'], machine['id']))
                                logger.warning("Mac address list (without duplicate)"\
                                    " for machine %s : %s" %(machine['id'], results))
                            else:
                                logger.debug("Mac address list for machine %s : %s" %(machine['id'],
                                                                                      results))
                            results = result[0].split(",")
                            logger.debug("Mac address list for machine %s : %s" %(machine['id'], results))
                            uuid = ''
                            btestfindcomputer = False
                            for t in results:
                                logger.debug("Get GLPI computer id for mac address %s"%t)
                                if t in xmppobject.blacklisted_mac_addresses: continue
                                computer = getComputerByMac(t)
                                if computer is not None:
                                    logger.debug("Computer found : #%s" %computer.id)
                                    jidrs = str(jid.JID(data['deployment']).user)
                                    jidm = jid.JID(data['from']).domain
                                    jidrs = "%s@%s" % (jidrs, jidm)
                                    uuid = 'UUID' + str(computer.id)
                                    logger.debug("** Update uuid %s for machine %s " %
                                                    (uuid, msg['from'].bare))
                                    XmppMasterDatabase().updateMachineidinventory(uuid, machine['id'])
                                    btestfindcomputer=True
                                    break;
                                else:
                                    logger.debug("No computer found in glpi")
                                    logger.debug("** Call inventory on %s" % msg['from'].bare)
                                    callinventory(xmppobject, data['from'])
                            if btestfindcomputer:
                                callInstallConfGuacamole(xmppobject,
                                                        jidrs,
                                                        {  'hostname': data['information']['info']['hostname'],
                                                            'machine_ip': data['xmppip'],
                                                            'uuid': str(computer.id),
                                                            'remoteservice': data['remoteservice'],
                                                            'platform' : data['platform'],
                                                            'os' : data['information']['info']['os']})
                    return

            if XmppMasterDatabase().getPresencejiduser(msg['from'].user):
                logger.debug("Machine idem jid, domain change %s" % msg['from'].bare)
                # The registration of the machine in database must be deleted, so it is updated.
                XmppMasterDatabase().delPresenceMachinebyjiduser(msg['from'].user)

            """ Check machine information from agent """
            logger.debug(
                "** Processing and check machine information from agent and "\
                    "the registry into database.")
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
            if not 'keysyncthing' in data:
                if 'information' in data and 'keysyncthing' in data['information']:
                    data['keysyncthing'] = data['information']['keysyncthing']
                else:
                    data['keysyncthing'] = ""
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
                    logger.info("add user : %s for machine : %s "\
                        "country_name : %s" % (data['information']['users'][0],
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
                                                    moderelayserver=moderelayserver,
                                                    keysyncthing=data['keysyncthing']
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

            logger.debug("=============")
            logger.debug("=============")
            logger.debug("Case 2 : The machine %s is not existing in base"%str(msg['from']))
            logger.debug("Create it and update it's uuid_inventory_machine")
            logger.debug("=============")
            logger.debug("=============")
            logger.debug("Adding new machine presence into machines table")
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
                                                                lastuser=data['lastusersession'],
                                                                keysyncthing=data['keysyncthing']
                                                                )
            if idmachine != -1:
                logger.debug("Machine %s added to machines table"%idmachine)
                if useradd != -1:
                    XmppMasterDatabase().hasmachineusers(useradd, idmachine)
                else:
                    logger.error("** Not user found for the machine")
                    return
                for i in data['information']["listipinfo"]:
                    try:
                        broadcast = i['broadcast']
                    except Exception:
                        broadcast = ''
                    logger.debug("** Add interface %s in database for machine %s" %
                                    (str(i['macaddress']), msg['from'].bare))
                    logger.debug("Add network card %s to the machine #%s"%(i['macaddress'], idmachine))
                    XmppMasterDatabase().addPresenceNetwork(i['macaddress'],
                                                            i['ipaddress'],
                                                            broadcast, i['gateway'],
                                                            i['mask'],
                                                            i['macnotshortened'],
                                                            idmachine)
                if data['agenttype'] != "relayserver":
                    # Update the machine uuid : for consistency with inventory
                    # call Guacamole config
                    # or add inventory
                    #logger.debug(
                        #"** Update the machine uuid : for consistency with inventory\n"\
                        #     "call Guacamole config\nor add inventory")
                    logger.debug("List the mac addresses for the machine #%s"%idmachine)
                    result = XmppMasterDatabase().listMacAdressforMachine(idmachine)
                    results = result[0].split(",")

                    uuid = ''
                    btestfindcomputer = False
                    for t in results:
                        logger.debug("Get the machine which has the specified mac address : %s"%t)
                        if t in xmppobject.blacklisted_mac_addresses: continue
                        computer = getComputerByMac(t)
                        if computer != None:
                            logger.debug("Id found : %s"%computer.id)
                            jidrs = str(jid.JID(data['deployment']).user)
                            jidm = jid.JID(data['from']).domain
                            jidrs = "%s@%s" % (jidrs, jidm)
                            uuid = 'UUID' + str(computer.id)
                            logger.debug("** Update uuid %s for machine %s " %
                                            (uuid, msg['from'].bare))

                            XmppMasterDatabase().updateMachineidinventory(uuid, idmachine)
                            btestfindcomputer = True
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
                            XmppMasterDatabase().setlogxmpp("Remote Service <b>%s</b>"\
                                " : for [machine : %s][RS : %s]" % (data['remoteservice'],
                                                                    data['information']['info']['hostname'],
                                                                    jidrs),
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
                    if btestfindcomputer == True:
                        callInstallConfGuacamole(xmppobject,
                                                jidrs,
                                                {  'hostname': data['information']['info']['hostname'],
                                                'machine_ip': data['xmppip'],
                                                'uuid': str(computer.id),
                                                'remoteservice': data['remoteservice'],
                                                'platform' : data['platform'],
                                                'os' : data['information']['info']['os']})
            else:
                logger.error("** Database registration error")
                return
            pluginfunction=[str("plugin_%s"%x) for x in xmppobject.pluginlistunregistered]
            logger.debug("call plugin for a machine not present..")
            for function_plugin in pluginfunction:
                try:
                    if hasattr(xmppobject, function_plugin):
                        if function_plugin == 'plugin_showregistration':
                            if logger.level == logging.DEBUG:
                                logger.debug("call plugin %s"%function_plugin)
                                getattr(xmppobject, function_plugin)(msg, data)
                        else:
                            logger.debug("call plugin %s"%function_plugin)
                            getattr(xmppobject, function_plugin)(msg, data)
                    else:
                        logger.warning("the %s plugin is not called"%function_plugin)
                        logger.warning("verify why plugging %s"\
                            " has no function %s"%(function_plugin,
                                                    function_plugin))
                except Exception:
                    logger.error("\n%s"%(traceback.format_exc()))

    except Exception as e:
        logger.error("machine info %s\n%s" % (str(e),traceback.format_exc()))

def getComputerByMac( mac):
    logger.debug("Asking to glpi the machine list for specified mac ...")
    ret = Glpi().getMachineByMacAddress('imaging_module', mac)
    if type(ret) == list:
        if len(ret) != 0:
            return ret[0]
        else:
            return None

    logger.debug("Glpi returned : %s"%ret)
    return ret

def callInstallConfGuacamole(xmppobject, torelayserver, data):
    try:
        body = {'action': 'guacamoleconf',
                'sessionid': getRandomName(5, "guacamoleconf"),
                'data': data}
        xmppobject.send_message(mto=torelayserver,
                            mbody=json.dumps(body),
                            mtype='chat')
    except Exception:
        logger.error("\n%s"%(traceback.format_exc()))

def callinventory(xmppobject,  to):
    try:
        body = {'action': 'inventory',
                'sessionid': getRandomName(5, "inventory"),
                'data': {}}
        xmppobject.send_message(mto=to,
                            mbody=json.dumps(body),
                            mtype='chat')
    except Exception:
        logger.error("\n%s"%(traceback.format_exc()))


def data_struct_message(action, data = {}, ret=0, base64 = False, sessionid = None):
    if sessionid == None or sessionid == "" or not isinstance(sessionid, basestring):
        sessionid = action.strip().replace(" ", "")
    return { 'action' : action,
             'data' : data,
             'ret' : 0,
             "base64" : False,
             "sessionid" : getRandomName(4,sessionid) }

def handlerkioskpresence(xmppobject,
                         jid,
                         id,
                         os,
                         hostname,
                         uuid_inventorymachine,
                         agenttype,
                         classutil,
                         fromplugin = False):
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
                                             sessionid = getRandomName(6,
                                                                       "initialisation_kiosk"))
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
                                                           {'hide_win_updates': True,
                                                            'history_delta': ''})
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

def __search_software_in_glpi(list_software_glpi, packageprofile, structuredatakiosk):
    structuredatakioskelement={ 'name': packageprofile[0],
                                "action" : [],
                                'uuid':  packageprofile[6],
                                'description': packageprofile[2],
                                "version" : packageprofile[3]
                               }
    patternname = re.compile("(?i)" + packageprofile[0])
    for soft_glpi in list_software_glpi:
        #TODO
        # Into the pulse package provide Vendor information for the software name
        # For now we use the package name which must match with glpi name
        if patternname.match(str(soft_glpi[0])) or patternname.match(str(soft_glpi[1])):
            # Process with this package which is installed on the machine
            # The package could be deleted
            structuredatakioskelement['icon'] =  'kiosk.png'
            structuredatakioskelement['action'].append('Delete')
            structuredatakioskelement['action'].append('Launch')
            # verification if update
            # compare the version
            #TODO
            # For now we use the package version.
            #Later the software version will be needed into the pulse package
            if LooseVersion(soft_glpi[2]) < LooseVersion(packageprofile[3]):
                structuredatakioskelement['action'].append('Update')
                logger.debug("the software version is superior "\
                    "to that installed on the machine %s : %s < %s"%(packageprofile[0],
                                                                     soft_glpi[2],
                                                                     LooseVersion(packageprofile[3])))
            break
    if len(structuredatakioskelement['action']) == 0:
        # The package defined for this profile is absent from the machine:
        if packageprofile[8] == "allowed":
            structuredatakioskelement['action'].append('Install')
        else:
            structuredatakioskelement['action'].append('Ask')
    return structuredatakioskelement

def read_conf_remote_registeryagent(xmppobject):
    logger.debug("Initialisation plugin :% s "%plugin["NAME"])
    namefichierconf = plugin['NAME'] + ".ini"
    pathfileconf = os.path.join( xmppobject.config.pathdirconffile, namefichierconf )
    if not os.path.isfile(pathfileconf):
        logger.error("plugin %s\nConfiguration file :" \
            "\n\t%s missing" \
        "\neg conf:\n[parameters]\n" \
            "pluginlistregistered = loadpluginlistversion, loadpluginschedulerlistversion,"\
                "loadautoupdate, showregistration\n" \
                "pluginlistunregistered = loadpluginlistversion, loadpluginschedulerlistversion,"\
                    "loadautoupdate, showregistration"%(plugin['NAME'], pathfileconf))
        logger.warning("default value for pluginlistregistered " \
            "is loadpluginlistversion, loadpluginschedulerlistversion, loadautoupdate, showregistration"\
            "\ndefault value for pluginlistunregistered"\
                "is loadpluginlistversion, loadpluginschedulerlistversion, loadautoupdate, showregistration")
        xmppobject.pluginlistregistered = ["loadpluginlistversion",
                                           "loadpluginschedulerlistversion",
                                           "loadautoupdate",
                                           "showregistration"]
        xmppobject.pluginlistunregistered = ["loadpluginlistversion",
                                             "loadpluginschedulerlistversion",
                                             "loadautoupdate",
                                             "showregistration"]
        xmppobject.check_uuidinventory = False
        xmppobject.blacklisted_mac_addresses= ["00:00:00:00:00:00"]
    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathfileconf)
        logger.debug("Config file %s for plugin %s"%(pathfileconf,
                                                     plugin["NAME"]))
        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")
            logger.debug("read file %s.local"%pathfileconf)

        if Config.has_option("parameters", "check_uuidinventory"):
            xmppobject.check_uuidinventory = Config.getboolean('parameters', 'check_uuidinventory')
        else:
            xmppobject.check_uuidinventory = False

        if Config.has_option("parameters", "pluginlistregistered"):
            pluginlistregistered = Config.get('parameters', 'pluginlistregistered')
        else:
            pluginlistregistered = "loadpluginlistversion, loadpluginschedulerlistversion,"\
                " loadautoupdate, showregistration"
        xmppobject.pluginlistregistered = [x.strip() for x in pluginlistregistered.split(',')]

        if Config.has_option("parameters", "pluginlistunregistered"):
            pluginlistunregistered = Config.get('parameters', 'pluginlistunregistered')
        else:
            pluginlistunregistered = "loadpluginlistversion, loadpluginschedulerlistversion,"\
                "loadautoupdate, showregistration"

        xmppobject.pluginlistunregistered = [x.strip() for x in pluginlistunregistered.split(',')]
        xmppobject.blacklisted_mac_addresses= []
        if Config.has_option("parameters", "blacklisted_mac_addresses"):
            blacklisted_mac_addresses = Config.get('parameters', 'blacklisted_mac_addresses')
        else:
            blacklisted_mac_addresses = "00:00:00:00:00:00"

        blacklisted_mac_addresses = blacklisted_mac_addresses.lower().replace(":","").replace(" ","")
        blacklisted_mac_addresses_list = [x.strip() for x in blacklisted_mac_addresses.split(',')]
        for t in blacklisted_mac_addresses_list:
            if len(t) == 12:
                macadrs = t[0:2]+":"+t[2:4]+":"+t[4:6]+":"+t[6:8]+":"+t[8:10]+":"+t[10:12]
                xmppobject.blacklisted_mac_addresses.append(macadrs)
            else:
                logger.warning("the mac address in blacklisted_mac_addresses parameter is bad format for value %s"%t )
        if "00:00:00:00:00:00" not in xmppobject.blacklisted_mac_addresses:
            xmppobject.blacklisted_mac_addresses.insert(0,"00:00:00:00:00:00")
    xmppobject.blacklisted_mac_addresses=list(set(xmppobject.blacklisted_mac_addresses))
    logger.debug("plugin list registered is %s"%xmppobject.pluginlistregistered)
    logger.debug("plugin list unregistered is %s"%xmppobject.pluginlistunregistered)
