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
# file : /common/plugin_updateagent.py
import os
import sys
import logging
import json
import zlib
import base64
import traceback
from lib.utils import file_put_contents, getRandomName
from lib.update_remote_agent import Update_Remote_Agent

plugin={"VERSION": "1.36", 'VERSIONAGENT' : '2.0',  "NAME" : "updateagent", "TYPE" : "all", "waittingmax" : 35, "waittingmin" : 5}

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s"%(plugin, message['from']))
    logger.debug("###################################################")
    logger.debug("%s"%json.dumps(data, indent =4))

    if "subaction" in data :
        if data['subaction'] == "descriptor":
            difference = { }
            supprimefileimage = []
            file_put_contents(os.path.join(objectxmpp.pathagent, "BOOL_UPDATE_AGENT"),
                              "use file boolean update. enable verify update.")
            if 'version' in data['descriptoragent']:
                #copy version agent master to image
                vers = (data['descriptoragent']['version']).replace("\n","").replace("\r","").strip()
                file_put_contents(os.path.join(objectxmpp.img_agent, "agentversion"),vers)
                file_put_contents(os.path.join(objectxmpp.pathagent, "agentversion"),vers)
            # on genere descriptor actuel de l image
            objdescriptorimage = Update_Remote_Agent(objectxmpp.img_agent)
            descriptorimage = objdescriptorimage.get_md5_descriptor_agent()
            # on recoit le nouveau descripteur depuis base de l'agent.
            objectxmpp.descriptor_master = data['descriptoragent']

            # il faut supprimer les fichier dans l'image qui ont ete supprimer dans la base.
            # on recherche les differences entre base de l'agent et l'image de la base.

            for directory_agent in objectxmpp.descriptor_master:
                if directory_agent  in ["fingerprint",
                                        "version",
                                        "version_agent"]:
                    continue

                diff, supp = search_action_on_agent_cp_and_del( objectxmpp.descriptor_master[directory_agent],
                                                                descriptorimage[directory_agent] )
                if directory_agent == "program_agent":
                    dirname = ""
                elif directory_agent == "lib_agent":
                    dirname = "lib"
                elif directory_agent == "script_agent":
                    dirname = "script"
                supp2 = [ os.path.join(objectxmpp.img_agent, dirname ,x)  for x in supp ]
                difference[directory_agent] = diff
                supprimefileimage.extend(supp2)
                for delfile in supp2:
                    try:
                        os.remove(delfile)
                    except:
                        pass
            logger.debug("delete unnecessary files in image %s"%json.dumps(supprimefileimage, indent = 4))

            if len(supprimefileimage) != 0:
                #on genere le descripteur de l'image, on a supprimer les fichiers qui sont dans l'image et pas dans la l'agent base
                objdescriptorimage = Update_Remote_Agent(objectxmpp.img_agent)
                descriptorimage = objdescriptorimage.get_md5_descriptor_agent()

                objectxmpp.Update_Remote_Agentlist = Update_Remote_Agent(objectxmpp.pathagent)
                descriptoragent = objectxmpp.Update_Remote_Agentlist.get_md5_descriptor_agent()

                # on regarde si il y a des diff entre img, base, et agent
                if (objectxmpp.descriptor_master['fingerprint'] == descriptorimage['fingerprint']) and\
                   ( objectxmpp.descriptor_master['fingerprint'] != descriptoragent['fingerprint']):
                    # on peut mettre a jour l'agent suite a une suppression de fichier inutile
                    objectxmpp.reinstall_agent()

            logger.debug("to updating files %s"%json.dumps(difference, indent = 4))
            try :
                # on demande les fichiers differents pour la mise a jour de l'image
                if len(difference['program_agent']) != 0 or \
                    len(difference['lib_agent']) != 0 or \
                        len(difference['script_agent']) != 0:
                    # demande de mise à jour.
                    # todo send message only files for updating.
                    # call resultupdateagent
                    msgupdate_me = { 'action': "result%s"%action,
                                    'sessionid': sessionid,
                                    'data' :  { "subaction" : "update_me",
                                                "descriptoragent" : difference },
                                    'ret' : 0,
                                    'base64' : False }
                    # renvoi descriptor pour demander la mise a jour
                    try:
                        agent_installor = objectxmpp.sub_registration
                    except AttributeError:
                        agent_installor = "master@pulse/MASTER"
                    if 'ars_update' in data and data['ars_update'] != "" :
                        agent_installor = data['ars_update']
                        msgupdate_me['action'] = "relayupdateagent"
                    objectxmpp.send_message( mto=agent_installor,
                                             mbody=json.dumps(msgupdate_me),
                                             mtype='chat')
                    return
                else:
                    objdescriptorimage = Update_Remote_Agent(objectxmpp.img_agent)
                    descriptorimage = objdescriptorimage.get_md5_descriptor_agent()

                    objectxmpp.Update_Remote_Agentlist = Update_Remote_Agent(objectxmpp.pathagent)
                    descriptoragent = objectxmpp.Update_Remote_Agentlist.get_md5_descriptor_agent()

                    # on regarde si il y a des diff entre img, base, et agent
                    if (objectxmpp.descriptor_master['fingerprint'] == descriptorimage['fingerprint']) and\
                    ( objectxmpp.descriptor_master['fingerprint'] != descriptoragent['fingerprint']):
                        # on peut mettre a jour l'agent suite a une suppression de fichier inutile
                        objectxmpp.reinstall_agent()
                    return
            except Exception as e:
                logger.error(str(e))
                traceback.print_exc(file=sys.stdout)
        elif data['subaction'] == "install_lib_agent":
            if not ('namescript' in data and data['namescript'] != ""):
                logger.error("update agent install lib name missing")
                return
            else:
                content = zlib.decompress(base64.b64decode(data['content']))
                dump_file_in_img(objectxmpp, data['namescript'], content, "lib_agent")
        elif data['subaction'] == "install_program_agent":
            if not ('namescript' in data and data['namescript'] != ""):
                logger.error("update agent install program name missing")
                return
            else:
                content = zlib.decompress(base64.b64decode(data['content']))
                dump_file_in_img(objectxmpp, data['namescript'], content, "program_agent")
        elif data['subaction'] == "install_script_agent":
            if not ('namescript' in data and data['namescript'] != ""):
                logger.error("updateagent install script name missing")
                return
            else:
                content = zlib.decompress(base64.b64decode(data['content']))
                dump_file_in_img(objectxmpp, data['namescript'], content, "script_agent")
        elif data['subaction'] == "ars_update":
            #verify agent type relayserver.
            logger.debug( "recu update agent from %s"\
                  " for update agent %s "\
                      "[ descriptor %s ]"%( message['from'],
                                            data['jidagent'],
                                            data['descriptoragent']))
            senddescriptormd5(objectxmpp, data)

def search_action_on_agent_cp_and_del(fromimg, frommachine):
    """
        return 2 lists
        list files to copi from img to mach
        list files to supp in mach
    """
    replace_file_mach_by_file_img = []
    file_missing_in_mach = []
    file_supp_in_mach = []
    # il y aura 1 ou plusieurs fichier a supprimer dans l'agent.
    # search fiichier devenu inutile
    for namefichier in frommachine:
        if namefichier in fromimg:
            # fichier dans les 2 cotes
            # on verifie si on doit remplacer:
            if frommachine[namefichier] != fromimg[namefichier]:
                # on doit le remplacer
                replace_file_mach_by_file_img.append(namefichier)
        else:
            file_supp_in_mach.append(namefichier)
    for namefichier in fromimg:
        #search fichier missing dans mach
        if not namefichier in frommachine:
            file_missing_in_mach.append(namefichier)
    #les fichiers manquant dans machine sont aussi des fichier a rajouter.
    fichier_to_copie =  list(replace_file_mach_by_file_img)
    fichier_to_copie.extend(file_missing_in_mach)
    return fichier_to_copie, file_supp_in_mach

def dump_file_in_img(objectxmpp, namescript, content, typescript):
    if typescript == "program_agent":
        # install script program
        file_mane = os.path.join(objectxmpp.img_agent, namescript)
        logger.debug("dump file %s to %s"%(namescript, file_mane))
    elif typescript == "script_agent":
        # install script program
        file_mane = os.path.join(objectxmpp.img_agent, "script", namescript)
        logger.debug("dump file %s to %s"%(namescript, file_mane))
    elif typescript == "lib_agent":
        # install script program
        file_mane = os.path.join(objectxmpp.img_agent, "lib", namescript)
        logger.debug("dump file %s to %s"%(namescript, file_mane))
    if 'file_mane' in locals():
        filescript = open(file_mane, "wb")
        filescript.write(content)
        filescript.close()
        newobjdescriptorimage = Update_Remote_Agent(objectxmpp.img_agent)
        if newobjdescriptorimage.get_fingerprint_agent_base() == objectxmpp.descriptor_master['fingerprint']:
            objectxmpp.reinstall_agent()
    else:
        logger.error("dump file type missing")

def senddescriptormd5(objectxmpp, data):
    """
    send the agent's figerprint  descriptor in database to the machine for update
    Update remote agent
    """
    objectxmpp.Update_Remote_Agentbase = Update_Remote_Agent(objectxmpp.config.diragentbase)
    descriptoragentbase = objectxmpp.Update_Remote_Agentbase.get_md5_descriptor_agent()
    datasend = {"action": "updateagent",
                "data": { 'subaction': 'descriptor',
                          'descriptoragent': descriptoragentbase,
                          'ars_update' : data['ars_update']
                          },
                'ret': 0,
                'sessionid': getRandomName(5, "updateagent")}
    # Send catalog of files.
    logger.debug("Send descriptor to agent [%s] for update" % data['jidagent'])
    objectxmpp.send_message(data['jidagent'],
                        mbody=json.dumps(datasend),
                        mtype='chat')
