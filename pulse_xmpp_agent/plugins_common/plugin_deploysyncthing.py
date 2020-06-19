# -*- coding: utf-8 -*-
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
# file : /common/deploysyncthing.py

import sys
import os
import logging
import json
import traceback
from lib import utils, \
                managepackage
from sleekxmpp import jid

plugin={"VERSION": "2.0", 'VERSIONAGENT' : '2.0.0', "NAME" : "deploysyncthing", "TYPE" : "all"}

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s"%(plugin, message['from']))
    logger.debug("sessionid : %s"%sessionid)
    logger.debug("###################################################")
    data['sessionid'] = sessionid
    datastring =  json.dumps(data, indent = 4)
    logger.debug("data in : %s"%datastring)
    if objectxmpp.config.agenttype in ['machine']:
        try:
            objectxmpp.config.syncthing_on
        except NameError:
            objectxmpp.config.syncthing_on = False
        if not objectxmpp.config.syncthing_on:
            logger.warning("configuration syncthing off"\
                " on %s: sessionid : %s"%(sessionid,
                                          objectxmpp.boundjid.bare))
        logger.debug("#################AGENT MACHINE#####################")
        if "subaction" in data :
            logger.debug("subaction : %s"%data['subaction'])
            if data['subaction'] == "notify_machine_deploy_syncthing":
                if not objectxmpp.config.syncthing_on:
                    objectxmpp.xmpplog("<span class='log_err'>"\
                        "Syncthing enabled parameter: no. "\
                            "Not creating descriptor file</span>",
                                        type='deploy',
                                        sessionname=sessionid,
                                        priority=-1,
                                        action="xmpplog",
                                        who="",
                                        how="",
                                        why=objectxmpp.boundjid.bare,
                                        module="Deployment | Syncthing",
                                        date=None,
                                        fromuser="",
                                        touser="")
                    objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                        type = 'deploy',
                                        sessionname = sessionid,
                                        priority = -1,
                                        action = "xmpplog",
                                        who = objectxmpp.boundjid.bare,
                                        how = "",
                                        why = "",
                                        module = "Deployment | Terminate"\
                                            " | Notify | Syncthing",
                                        date = None ,
                                        fromuser = "",
                                        touser = "")
                    data['jidrelay'] = "%s"%message['from']
                    signalendsessionforARS(data , objectxmpp, sessionid, error = True)
                    return

                objectxmpp.syncthing.get_db_completion(data['id_deploy'],
                                                       objectxmpp.syncthing.device_id)
                # savedata fichier sessionid.ars
                namesessionidars = os.path.join(objectxmpp.dirsyncthing,
                                                "%s.ars"%sessionid)
                utils.file_put_contents(namesessionidars, datastring)
                logger.debug("Creating file %s"%namesessionidars)
                objectxmpp.xmpplog("Creating ars file %s"%namesessionidars,
                                    type='deploy',
                                    sessionname=sessionid,
                                    priority=-1,
                                    action="xmpplog",
                                    who="",
                                    how="",
                                    why=objectxmpp.boundjid.bare,
                                    module="Deployment | Syncthing",
                                    date=None,
                                    fromuser="",
                                    touser="")
            elif data['subaction'] == "cleandeploy":
                if not objectxmpp.config.syncthing_on:
                    return
                #TODO: this action will be implemented
                # call suppression partage syncthing
                if 'iddeploy' in data:
                    logger.debug("Delete share %s if exist"%data['iddeploy'])
                    #objectxmpp.syncthing.delete_folder_id_pulsedeploy(data['iddeploy'])
                    #objectxmpp.syncthing.del_folder(data['iddeploy'])
                    objectxmpp.syncthing.delete_folder_pulse_deploy(data['iddeploy'])
                    #call function nettoyage old partage files.
        else:
            if not objectxmpp.config.syncthing_on:
                    objectxmpp.xmpplog("<span class='log_err'>"\
                        "Syncthing enabled parameter: no. "\
                            "Not creating ars file</span>",
                                        type='deploy',
                                        sessionname=sessionid,
                                        priority=-1,
                                        action="xmpplog",
                                        who="",
                                        how="",
                                        why=objectxmpp.boundjid.bare,
                                        module="Deployment | Syncthing",
                                        date=None,
                                        fromuser="",
                                        touser="")
                    objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                        type = 'deploy',
                                        sessionname = sessionid,
                                        priority = -1,
                                        action = "xmpplog",
                                        who = objectxmpp.boundjid.bare,
                                        how = "",
                                        why = "",
                                        module = "Deployment | Terminate"\
                                            " | Notify | Syncthing",
                                        date = None ,
                                        fromuser = "",
                                        touser = "")
                    data['jidrelay'] = "%s"%message['from']
                    signalendsessionforARS(data , objectxmpp, sessionid, error = True)
                    return
            namesessioniddescriptor = os.path.join(objectxmpp.dirsyncthing,"%s.descriptor"%sessionid)
            utils.file_put_contents(namesessioniddescriptor, json.dumps(data, indent =4))
            logger.debug("creation file %s"%namesessioniddescriptor)
            objectxmpp.xmpplog( "Creating descriptor file %s"%namesessioniddescriptor,
                                type='deploy',
                                sessionname=sessionid,
                                priority=-1,
                                action="xmpplog",
                                who="",
                                how="",
                                why=objectxmpp.boundjid.bare,
                                module="Deployment | Syncthing",
                                date=None,
                                fromuser="",
                                touser="")
    else:
        try:
            logger.debug("##############AGENT RELAY SERVER###################")
            """ les devices des autre ARS sont connue, on initialise uniquement le folder."""
            basesyncthing = "/var/lib/syncthing/partagedeploy"
            if not os.path.exists(basesyncthing):
                os.makedirs(basesyncthing)
            if "subaction" in data :
                logger.debug("subaction : %s"%data['subaction'])
                if data['subaction'] == "syncthingdeploycluster":
                    packagedir = managepackage.managepackage.packagedir()
                    # creation fichier de partages syncthing
                    repertorypartage = os.path.join(basesyncthing,data['repertoiredeploy'] )
                    if not os.path.exists(repertorypartage):
                        os.makedirs(repertorypartage)
                    cmd = "touch %s"%os.path.join(repertorypartage,'.stfolder')
                    logger.debug("cmd : %s"%cmd)
                    obj = utils.simplecommand(cmd)
                    if int(obj['code']) != 0:
                        logger.warning(obj['result'])
                    list_of_deployment_packages =\
                        managepackage.search_list_of_deployment_packages(data['packagedeploy']).\
                            search()
                    logger.warning("copy to repertorypartage")
                    #on copy les packages dans le repertoire de  partages"
                    for z in list_of_deployment_packages:
                        repsrc = os.path.join(packagedir,str(z) )
                        cmd = "rsync -r %s %s/"%( repsrc , repertorypartage)
                        logger.debug("cmd : %s"%cmd)
                        obj = utils.simplecommand(cmd)
                        if int(obj['code']) != 0:
                            logger.warning(obj['result'])
                        else:
                            objectxmpp.xmpplog( "ARS %s share folder %s"%(objectxmpp.boundjid.bare,
                                                repertorypartage),
                                                type='deploy',
                                                sessionname=sessionid,
                                                priority=-1,
                                                action="xmpplog",
                                                who="",
                                                how="",
                                                why=objectxmpp.boundjid.bare,
                                                module="Deployment | Syncthing",
                                                date=None,
                                                fromuser="",
                                                touser="")
                    cmd ="chown syncthing:syncthing -R %s"%repertorypartage
                    logger.debug("cmd : %s"%cmd)
                    obj = utils.simplecommand(cmd)
                    if int(obj['code']) != 0:
                        logger.warning(obj['result'])
                    # creation fichier .stfolder

                    #addition des devices. add device ARS si non exist.
                    #creation du partage pour cet
                    if data['elected'].split('/')[0] == objectxmpp.boundjid.bare:
                        typefolder="master"
                    else:
                        typefolder="slave"
                    #creation du folder
                    newfolder = objectxmpp.syncthing.\
                        create_template_struct_folder(data['repertoiredeploy'], # or data['packagedeploy']
                                                    repertorypartage,
                                                    id=data['repertoiredeploy'],
                                                    typefolder=typefolder )
                    objectxmpp.syncthing.add_folder_dict_if_not_exist_id(newfolder)


                    #add device cluster ars in new partage folder
                    #ajoute des tas de fois cette device dans le folder.
                    for keyclustersyncthing in data['listkey']:
                        if keyclustersyncthing != "\"\"":
                            logger.info("\n ADD DEVICE IN FOLDER %s  %s\n"%(keyclustersyncthing,
                                                                            data['repertoiredeploy']))
                            logger.info("ADD DEVICE ARS %s in folder %s"%(keyclustersyncthing,
                                                                        data['repertoiredeploy']))
                            objectxmpp.syncthing.add_device_in_folder_if_not_exist( data['repertoiredeploy'],
                                                                                    keyclustersyncthing,
                                                                                    introducedBy = "")

                    for machine in data['machinespartage']:
                        #add device dans folder
                        if machine['devi'] != "\"\"":
                            logger.info("ADD DEVICE MACHINE %s in folder %s"%(machine['devi'],
                                                                                                     data['repertoiredeploy']))

                            objectxmpp.syncthing.add_device_in_folder_if_not_exist( data['repertoiredeploy'],
                                                                                    machine['devi'],
                                                                                    introducedBy = "")

                        #add device
                        namemachine = jid.JID(machine['mach']).resource
                        #if objectxmpp.boundjid.bare == "rspulse@pulse":
                        if jid.JID(machine['mach']).bare == "rspulse@pulse":
                            namemachine = "pulse"
                        if namemachine=="":
                            namemachine = machine['mach']
                        if machine['devi'] != "\"\"":
                            logger.debug("ADD DEVICE  %s in DEVICE %s"%(machine['devi'],
                                                                        namemachine))

                            #add_device_syncthing(objectxmpp.syncthing,
                                                    # machine['devi'],
                                                    # namemachine,
                                                    # config)

                            objectxmpp.syncthing.add_device_syncthing(machine['devi'],
                                                  namemachine)

                        #create message for machine
                        datasend = {'action' : "deploysyncthing",
                                    "sessionid" : machine['ses'],
                                    "ret" : 0,
                                    "base64" : False,
                                    "data" : { "subaction" : "notify_machine_deploy_syncthing",
                                               "id_deploy" : data['repertoiredeploy'],
                                               "namedeploy" : data['namedeploy'],
                                               "packagedeploy" : data['packagedeploy'],
                                               "ARS" : machine['rel'],
                                               "mach" : machine['mach'],
                                               "iddeploybase" : data['id']}}
                        logger.debug("SEND ARS FILE SYNCTHING TO MACHINE %s"%machine['mach'])
                        objectxmpp.send_message(mto=machine['mach'],
                                                mbody=json.dumps(datasend),
                                                mtype='chat')
                        logger.debug("add device %s for machine %s"%(machine['devi'],
                                                                          machine['mach']))
                    objectxmpp.syncthing.maxSendKbps( kb=0)

                    objectxmpp.syncthing.validate_chang_config()
                elif data['subaction'] == "cleandeploy":
                    objectxmpp.syncthing.maxSendKbps( kb=0)
                    #TODO: this action will be implemented
                    # call suppression partage syncthing
                    if 'iddeploy' in data:
                        logger.debug("Delete partage %s if exist"%data['iddeploy'])
                        #objectxmpp.syncthing.delete_folder_id_pulsedeploy(data['iddeploy'])
                        objectxmpp.syncthing.delete_folder_pulse_deploy(data['iddeploy'])
                    messgagesend = {
                        "sessionid" : sessionid,
                        "action" : action,
                        "data" : { "subaction" : "cleandeploy",
                                "iddeploy" : data['iddeploy'] }
                    }
                    machineslist = data['jidmachines'].split(",")
                    relayslist   = data['jidrelays'].split(",")
                    nbrelaylist  = len(relayslist)
                    for index_relay_mach in  range(nbrelaylist):
                        if relayslist[index_relay_mach] == objectxmpp.boundjid.full:
                            #send message machine
                            logger.debug("send Delete partage %s on mach %s"%(data['iddeploy'],
                                                                              machineslist[index_relay_mach]))
                            logger.debug("send delete floder to machine %s"%machineslist[index_relay_mach])
                            objectxmpp.send_message(mto=machineslist[index_relay_mach],
                                                    mbody=json.dumps(messgagesend),
                                                    mtype='chat')
                elif data['subaction'] == "pausefolder":
                    if 'folder' in data:
                        #objectxmpp.syncthing.set_pause_folder(data['folder'], paused = True)
                        objectxmpp.syncthing.maxSendKbps( kb=1)
        except:
            logger.error("\n%s"%(traceback.format_exc()))
            raise

###############################################################
# syncthing function
###############################################################
def is_exist_folder_id(idfolder, config):
    for folder in config['folders']:
        if folder['id'] == idfolder:
            return True
    return False

def add_folder_dict_if_not_exist_id(dictaddfolder, config):
    if not is_exist_folder_id(dictaddfolder['id'], config):
        config['folders'].append(dictaddfolder)
        return True
    return False

def add_device_in_folder_if_not_exist( folderid,
                                          keydevice,
                                          config,
                                          introducedBy = ""):
        result = False
        for folder in config['folders']:
            if folderid == folder['id']:
                #folder trouve
                for device in folder['devices']:
                    if device['deviceID'] == keydevice:
                        #device existe
                        result = False
                new_device = {"deviceID": keydevice,
                                "introducedBy": introducedBy}
                folder['devices'].append(new_device)
                result =  True
        return result

def add_device_syncthing(   objctsycthing,
                            keydevicesyncthing,
                            namerelay,
                            config,
                            introducer = False,
                            autoAcceptFolders=False,
                            address = ["dynamic"]):
    # test si device existe
    for device in config['devices']:
        if device['deviceID'] == keydevicesyncthing:
            result = False
    logger.debug("add device syncthing %s"%keydevicesyncthing)
    dsyncthing_tmp = objctsycthing.create_template_struct_device(namerelay,
                                                        str(keydevicesyncthing),
                                                        introducer = introducer,
                                                        autoAcceptFolders=autoAcceptFolders,
                                                        address = address)

    logger.debug("add device [%s]syncthing to ars %s\n%s"%(keydevicesyncthing,
                                                            namerelay,
                                                            json.dumps(dsyncthing_tmp,
                                                                        indent = 4)))

    config['devices'].append(dsyncthing_tmp)
    return dsyncthing_tmp



def signalendsessionforARS(datasend , objectxmpp, sessionid, error = False):
    #termine sessionid sur ARS pour permettre autre deploiement
    try :
        msgsessionend = { 'action': "resultapplicationdeploymentjson",
                        'sessionid': sessionid,
                        'data' :  datasend,
                        'ret' : 255,
                        'base64' : False
                        }
        if error == False:
            msgsessionend['ret'] = 0
        datasend['endsession'] = True
        objectxmpp.send_message(mto=datasend['jidrelay'],
                                mbody=json.dumps(msgsessionend),
                                mtype='chat')
    except Exception as e:
        logger.debug(str(e))
        traceback.print_exc(file=sys.stdout)
