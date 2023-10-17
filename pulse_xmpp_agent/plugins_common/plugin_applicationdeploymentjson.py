# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import base64
import hashlib
import json
import sys, os
import socket
import logging
import pycurl
import platform
import urllib
import shutil
from lib.utils import file_get_contents
from urlparse import urlparse
from lib import utils, \
                managepackage, \
                grafcetdeploy
import copy
import traceback
import time
from subprocess import STDOUT, check_output

if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
    import grp
    import pwd
elif sys.platform.startswith('win'):
    import win32net

plugin = {"VERSION": "5.31", "NAME": "applicationdeploymentjson", "VERSIONAGENT": "2.0.0", "TYPE": "all"}

Globaldata = {'port_local': 22}
logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
"""
Plugin for deploying a package
"""
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    strjidagent = str(objectxmpp.boundjid.bare)
    if hasattr(objectxmpp.config, 'clients_ssh_port'):
        Globaldata['port_local'] = int(objectxmpp.config.clients_ssh_port)
        logger.debug("Clients SSH port %s"%Globaldata['port_local'])
    try:
        objectxmpp.config.reverseserver_ssh_port
    except:
        objectxmpp.config.reverseserver_ssh_port = 22
    try:
        objectxmpp.config.pushsubstitutionmethod
    except:
        objectxmpp.config.pushsubstitutionmethod = "pulldirect"

    if objectxmpp.config.agenttype in ['machine']:
        logger.debug("###################################################")
        logger.debug("call %s from %s" % (plugin, message['from']))
        logger.debug("###################################################")
        logger.debug("#################AGENT MACHINE#####################")
        logger.debug("###################################################")
        if 'portreversessh' in data:
            objectxmpp.config.reverseserver_ssh_port = data['portreversessh']
        # If actionscheduler is set, the message comes from master to specify what to do
        # between: run, abandonmentdeploy and pause
        if 'actionscheduler' in data:
            if data['actionscheduler'] == "run":
                logger.debug("RUN DEPLOY")
                sessioninfo = objectxmpp.Deploybasesched.get_sesionscheduler(sessionid)
                if sessioninfo == "":
                    objectxmpp.xmpplog('<span class="log_err">Package delayed execution error : session missing</span>',
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Error  | Notify | Execution",
                                       date=None,
                                       fromuser="AM %s" % strjidagent,
                                       touser="")
                    objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Terminate |Notify",
                                       date=None,
                                       fromuser="AM %s" % strjidagent,
                                       touser="")
                    signalendsessionforARS(data, objectxmpp, sessionid, error=True)
                    return
                else:
                    datajson = json.loads(sessioninfo)
                    datasend = datajson

                    objectxmpp.Deploybasesched.del_sesionscheduler(sessionid)
                    initialisesequence(datasend, objectxmpp, sessionid)
                    return
            elif data['actionscheduler'] == "pause":

                return
            elif data['actionscheduler'] == "abandonmentdeploy":
                objectxmpp.xmpplog('<span class="log_err">Package delayed execution cancelled</span>',
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Error | Notify",
                                   date=None,
                                   fromuser="AM %s" % strjidagent,
                                   touser="")
                objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Terminate | Notify",
                                   date=None,
                                   fromuser="AM %s" % strjidagent,
                                   touser="")

                objectxmpp.Deploybasesched.del_sesionscheduler(sessionid)
                signalendsessionforARS(data, objectxmpp, sessionid, error=True)
            else:
                #supprime cet input
                objectxmpp.xmpplog('<span class="log_err">Package delayed execution error</span>',
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Error | Notify",
                                   date=None,
                                   fromuser="AM %s" % strjidagent,
                                   touser="")
                objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Terminate | Notify",
                                   date=None,
                                   fromuser="AM %s" % strjidagent,
                                   touser="")
                objectxmpp.Deploybasesched.del_sesionscheduler(sessionid)
                signalendsessionforARS(data, objectxmpp, sessionid, error=True)
            return


        #when dependence require, AM asks ARS for this dependency
        #If a dependency does not exist, relay server reports it by sending "error package missing"
        if 'descriptor' in data and data['descriptor'] == "error package missing":
            #package data['deploy'] is missing
            #termined le deploy
            objectxmpp.xmpplog('<span class="log_err">Deployment error : missing dependency [%s]</span>' % data['deploy'],
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               how="",
                               why="",
                               module="Deployment | Error | Dependencies | Transfer| Notify",
                               date=None,
                               fromuser="AM %s" % strjidagent,
                               touser="")
            if sessionid in objectxmpp.back_to_deploy:
                objectxmpp.xmpplog('<span class="log_err">List of abandoned dependencies %s</span>' % objectxmpp.back_to_deploy[sessionid]['Dependency'],
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Dependencies | Transfer | Notify",
                                   date=None,
                                   fromuser="AM %s" % strjidagent,
                                   touser="")
            objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               how="",
                               why="",
                               module="Deployment | Terminate | Notify",
                               date=None,
                               fromuser="AM %s" % strjidagent,
                               touser="")
            signalendsessionforARS(data, objectxmpp, sessionid, error=True)

            #clean session
            objectxmpp.session.clearnoevent(sessionid)
            #clean if not session
            utils.cleanbacktodeploy(objectxmpp)
            return

        # condition for quit deploy reinjection de message avec condition error
        # data is empty message for gestion des dependency
        if len(data) == 0:
            if 'msgstate' in message['body'] and 'msg' in message['body']['msgstate']  and message['body']['msgstate']['msg'].startswith("end error"):
                if message['body']['msgstate']['quitonerror']:
                    logger.debug("Quit session %s on error " % sessionid)
                    objectxmpp.xmpplog('<span class="log_err">Package execution error</span>',
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Error",
                                       date=None,
                                       fromuser="AM %s" % strjidagent,
                                       touser="")
                    if sessionid in objectxmpp.back_to_deploy:
                        objectxmpp.xmpplog('<span class="log_err">List of abandoned dependencies %s</span>' % objectxmpp.back_to_deploy[sessionid]['Dependency'],
                                           type='deploy',
                                           sessionname=sessionid,
                                           priority=-1,
                                           action="xmpplog",
                                           who=strjidagent,
                                           how="",
                                           why="",
                                           module="Deployment | Dependencies | Transfer | Notify",
                                           date=None,
                                           fromuser="AM %s" % strjidagent,
                                           touser="")
                    objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Terminate | Notify",
                                       date=None,
                                       fromuser="AM %s" % strjidagent,
                                       touser="")
                    objectxmpp.session.clearnoevent(sessionid)
                    utils.cleanbacktodeploy(objectxmpp)
                    return

            #signal deploy terminate si session n'ai pas dans back_to_deploy
            if sessionid not in objectxmpp.back_to_deploy:
                # Deployment to finish here.
                logger.debug("termine la session %s" % sessionid)
                objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Terminate | Notify",
                                   date=None,
                                   fromuser="AM %s" % strjidagent,
                                   touser="")
                objectxmpp.session.clearnoevent(sessionid)
                utils.cleanbacktodeploy(objectxmpp)
                return

            if sessionid in objectxmpp.back_to_deploy and 'Dependency' in objectxmpp.back_to_deploy[sessionid]:
                if len(objectxmpp.back_to_deploy[sessionid]['Dependency']) > 0:
                    loaddependency = objectxmpp.back_to_deploy[sessionid]['Dependency'].pop()
                    data = copy.deepcopy(objectxmpp.back_to_deploy[sessionid]['packagelist'][loaddependency])
                    objectxmpp.xmpplog('Dependency [%s] ' % (data['name']),
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Dependency",
                                       date=None,
                                       fromuser="AM %s" % strjidagent,
                                       touser="")
                    try:
                        objectxmpp.back_to_deploy[sessionid]['Dependency'].remove(loaddependency)
                    except Exception:
                        pass
                    del objectxmpp.back_to_deploy[sessionid]['packagelist'][loaddependency]
                    if len(objectxmpp.back_to_deploy[sessionid]['Dependency']) == 0:
                        del objectxmpp.back_to_deploy[sessionid]
                    utils.save_back_to_deploy(objectxmpp.back_to_deploy)
                    objectxmpp.session.sessionsetdata(sessionid, data)


        #il y a des dependences dans package
        if 'Dependency' in data['descriptor']['info'] and data['descriptor']['info']['Dependency']:
            # Not immediately deployed
            # The deployment is prepared for the next
            try:
                if sessionid not in objectxmpp.back_to_deploy:
                    objectxmpp.back_to_deploy[sessionid] = {}
                    objectxmpp.back_to_deploy[sessionid]['Dependency'] = []
                    objectxmpp.back_to_deploy[sessionid]['packagelist'] = {}

                data['deploy'] = data['path'].split("/")[-1]
                data['descriptor']['info']['Dependency'].reverse()
                data['descriptor']['info']['Dependency'].insert(0, data['deploy'])
                objectxmpp.back_to_deploy[sessionid]['Dependency'] = objectxmpp.back_to_deploy[sessionid]['Dependency'] + data['descriptor']['info']['Dependency']
                del data['descriptor']['info']['Dependency']
                logger.debug("Dependency deployement %s"%(objectxmpp.back_to_deploy[sessionid]['Dependency']))
                #global information to keep for this session


                if 'ipmachine' not in objectxmpp.back_to_deploy[sessionid]:
                    #on les sauves
                    #toutes les dependences du packet deploye hérite des priorites de ce packet.
                    objectxmpp.back_to_deploy[sessionid]['ipmachine'] = data['ipmachine']
                    objectxmpp.back_to_deploy[sessionid]['ipmaster'] = data['ipmaster']
                    objectxmpp.back_to_deploy[sessionid]['iprelay'] = data['iprelay']
                    objectxmpp.back_to_deploy[sessionid]['jidmachine'] = data['jidmachine']
                    objectxmpp.back_to_deploy[sessionid]['jidmaster'] = data['jidmaster']
                    objectxmpp.back_to_deploy[sessionid]['jidrelay'] = data['jidrelay']
                    objectxmpp.back_to_deploy[sessionid]['login'] = data['login']
                    objectxmpp.back_to_deploy[sessionid]['methodetransfert'] = data['methodetransfert']
                    objectxmpp.back_to_deploy[sessionid]['transfert'] = data['transfert']
                    objectxmpp.back_to_deploy[sessionid]['uuid'] = data['uuid']
                    objectxmpp.back_to_deploy[sessionid]['ippackageserver'] = data['ippackageserver']
                    objectxmpp.back_to_deploy[sessionid]['portpackageserver'] = data['portpackageserver']
                    if 'advanced' in data:
                        objectxmpp.back_to_deploy[sessionid]['advanced'] = data['advanced']
            except Exception as e:
                logger.error(str(e))

        if sessionid in objectxmpp.back_to_deploy and 'start' not in objectxmpp.back_to_deploy[sessionid]:
            #create list package deploy
            try:
                # Necessary datas are added.
                # If we do not have these data global has all the dislocation we add them.
                # Son applique a la dependence les proprietes du packages
                if 'ipmachine' not in data:
                    logger.debug("addition global informations for deploy mode push dependency")
                    data['ipmachine'] = objectxmpp.back_to_deploy[sessionid]['ipmachine']
                    data['ipmaster'] = objectxmpp.back_to_deploy[sessionid]['ipmaster']
                    data['iprelay'] = objectxmpp.back_to_deploy[sessionid]['iprelay']
                    data['jidmachine'] = objectxmpp.back_to_deploy[sessionid]['jidmachine']
                    data['jidmaster'] = objectxmpp.back_to_deploy[sessionid]['jidmaster']
                    data['login'] = objectxmpp.back_to_deploy[sessionid]['login']
                    data['methodetransfert'] = objectxmpp.back_to_deploy[sessionid]['methodetransfert']
                    data['transfert'] = objectxmpp.back_to_deploy[sessionid]['transfert']
                    data['uuid'] = objectxmpp.back_to_deploy[sessionid]['uuid']
                    data['jidrelay'] = objectxmpp.back_to_deploy[sessionid]['jidrelay']
                    data['ippackageserver'] = objectxmpp.back_to_deploy[sessionid]['ippackageserver']
                    data['portpackageserver'] = objectxmpp.back_to_deploy[sessionid]['portpackageserver']
                    if 'advanced' in objectxmpp.back_to_deploy[sessionid]:
                        data['advanced'] = objectxmpp.back_to_deploy[sessionid]['advanced']

                # Verify that for each Dependency one has its descriptor
                # Store the dependency descriptor in back_to_deploy object for the session
                data['deploy'] = data['path'].split("/")[-1]
                if data['deploy'] not in objectxmpp.back_to_deploy[sessionid]:
                    objectxmpp.back_to_deploy[sessionid]['packagelist'][data['deploy']] = data
                if 'count' not in objectxmpp.back_to_deploy[sessionid]:
                    #We use a counter to take a case where the dependencies loop.
                    objectxmpp.back_to_deploy[sessionid]['count'] = 0
                # Then we look in the list of descriptors if these data of each dependence are present
                for dependency in objectxmpp.back_to_deploy[sessionid]['Dependency']:
                    if dependency == "":
                        continue

                    if dependency not in objectxmpp.back_to_deploy[sessionid]['packagelist']:
                        # We ask the RS Package server to send us the package descriptor
                        datasend = {'action': "rsapplicationdeploymentjson",
                                    'sessionid': sessionid,
                                    'data': {'deploy': dependency},
                                    'ret': 0,
                                    'base64': False
                                    }
                        objectxmpp.back_to_deploy[sessionid]['count'] += 1
                        if objectxmpp.back_to_deploy[sessionid]['count'] > 30:
                            objectxmpp.xmpplog('Warning [%s] has cyclic dependencies' % (dependency),
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               how="",
                                               why="",
                                               module="Deployment | Dependency",
                                               date=None,
                                               fromuser="AM %s" % strjidagent,
                                               touser="")
                            return
                        # If it lacks a dependency descriptor it is requested to relay server
                        objectxmpp.send_message(mto=data['jidrelay'],
                                                mbody=json.dumps(datasend),
                                                mtype='chat')
                        if sessionid in objectxmpp.back_to_deploy:
                            utils.save_back_to_deploy(objectxmpp.back_to_deploy)
                        return
                else:
                    # All dependencies are taken into account.
                    # You must deploy the descriptors of the dependency list starting with the end (pop)
                    #objectxmpp.back_to_deploy[sessionid]['Dependency']
                    #logger.debug("Start Multi-dependency deployment.")
                    strdeploypack = []
                    packlistdescribemapdeploy = []
                    for k in objectxmpp.back_to_deploy[sessionid]['Dependency']:
                        if k not in packlistdescribemapdeploy:
                            packlistdescribemapdeploy.append(str(k))
                            strdeploypack.append(objectxmpp.back_to_deploy[sessionid]['packagelist'][k]['descriptor']['info']['software'])
                    objectxmpp.back_to_deploy[sessionid]['Dependency'] = packlistdescribemapdeploy
                    strdeploypack.reverse()
                    objectxmpp.xmpplog('(Preparing the deployment plan for %s : [%s])' % (strdeploypack[-1], ", ".join(strdeploypack)),
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment",
                                       date=None,
                                       fromuser="AM %s" % strjidagent,
                                       touser="")
                    data["plan"] = strdeploypack
                    logger.debug("Dependencies list %s" % (objectxmpp.back_to_deploy[sessionid]['Dependency']))
                    firstinstall = objectxmpp.back_to_deploy[sessionid]['Dependency'].pop()

                    objectxmpp.back_to_deploy[sessionid]['start'] = True

                    data = copy.deepcopy(objectxmpp.back_to_deploy[sessionid]['packagelist'][firstinstall])
                    #objectxmpp.xmpplog('! : first dependency [%s] '%(data['name']),
                    # type = 'deploy',
                    # sessionname = sessionid,
                    # priority = -1,
                    # action = "xmpplog",
                    # who = strjidagent,
                    # how = "",
                    # why = "",
                    # module = "Deployment",
                    # date=None,
                    # fromuser = data['name'],
                    # touser = "")
                    try:
                        # Removes all the occurrences of this package if it exists because it is installing
                        objectxmpp.back_to_deploy[sessionid]['Dependency'].remove(firstinstall)
                    except Exception:
                        pass
                    del(objectxmpp.back_to_deploy[sessionid]['packagelist'][firstinstall])
                    utils.save_back_to_deploy(objectxmpp.back_to_deploy)
            #########################################################
            except Exception as e:
                logger.error(str(e))

        if sessionid in objectxmpp.back_to_deploy:
            # Necessary datas are added.
            # If one has not in data this information is added.
            if 'ipmachine' not in data:
                logger.debug("addition global informations for deploy")
                data['ipmachine'] = objectxmpp.back_to_deploy[sessionid]['ipmachine']
                data['ipmaster'] = objectxmpp.back_to_deploy[sessionid]['ipmaster']
                data['iprelay'] = objectxmpp.back_to_deploy[sessionid]['iprelay']
                data['jidmachine'] = objectxmpp.back_to_deploy[sessionid]['jidmachine']
                data['jidmaster'] = objectxmpp.back_to_deploy[sessionid]['jidmaster']
                data['login'] = objectxmpp.back_to_deploy[sessionid]['login']
                data['methodetransfert'] = objectxmpp.back_to_deploy[sessionid]['methodetransfert']
                data['transfert'] = objectxmpp.back_to_deploy[sessionid]['transfert']
                data['uuid'] = objectxmpp.back_to_deploy[sessionid]['uuid']
                data['jidrelay'] = objectxmpp.back_to_deploy[sessionid]['jidrelay']
                data['ippackageserver'] = objectxmpp.back_to_deploy[sessionid]['ippackageserver']
                data['portpackageserver'] = objectxmpp.back_to_deploy[sessionid]['portpackageserver']
                if 'advanced' in objectxmpp.back_to_deploy[sessionid]:
                    data['advanced'] = objectxmpp.back_to_deploy[sessionid]['advanced']
            objectxmpp.session.sessionsetdata(sessionid, data)

        datasend = {'action': action,
                    'sessionid': sessionid,
                    'data': data,
                    'ret': 0,
                    'base64': False
                    }

        # Check if the descriptor is complete
        if 'descriptor' in data and 'advanced' not in data:
            objectxmpp.xmpplog('<span class="log_err">Abort deployement section avanced missing in descriptor</span>',
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               how="",
                               why="",
                               module="Deployment | Error",
                               date=None,
                               fromuser="AM %s" % strjidagent,
                               touser="")
            objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               how="",
                               why="",
                               module="Deployment | Terminate | Notify",
                               date=None,
                               fromuser="AM %s" % strjidagent,
                               touser="")
            objectxmpp.session.clearnoevent(sessionid)
            utils.cleanbacktodeploy(objectxmpp)
            return

        if 'stepcurrent' not in datasend['data']:
            if not cleandescriptor(data):
                objectxmpp.xmpplog('<span class="log_err">Descriptor error: descriptor for OS %s missing</span>' % sys.platform,
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=0,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment",
                                   date=None,
                                   fromuser="AM %s" % strjidagent,
                                   touser="")
                datasend = {'action': "result" + action,
                            'sessionid': sessionid,
                            'data': data,
                            'ret': -1,
                            'base64': False
                            }
                datasend['data']['descriptor']['sequence'] = [{"action": "ERROR",
                                                               "description": "Descriptor missing for platform %s os[%s]" % (sys.platform, platform.platform()),
                                                               "step": -1,
                                                               "completed": 1}]
                objectxmpp.send_message(mto=data['jidmaster'],
                                        mbody=json.dumps(datasend),
                                        mtype='chat')
                datasend['data']['action'] = datasend['action']
                datasend['action'] = "xmpplog"
                datasend['data']['ret'] = -1
                datasend['data']['sessionid'] = sessionid
                objectxmpp.send_message(mto=objectxmpp.sub_logger,
                                        mbody=json.dumps(datasend),
                                        mtype='chat')
                objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Terminate | Notify",
                                   date=None,
                                   fromuser="AM %s" % strjidagent,
                                   touser="")
                signalendsessionforARS(data, objectxmpp, sessionid, error=True)
                return
            else:
                datasend = {'action': action,
                            'sessionid': sessionid,
                            'data': data,
                            'ret': 0,
                            'base64': False
                            }
            datasend['data']['pathpackageonmachine'] = os.path.join(managepackage.managepackage.packagedir(), data['path'].split('/')[-1])
            # le transfert pull direct ou pullcurl doit etre traite ici
            if data['transfert'] and \
                data['methodetransfert'] in ["pullcurl", "pulldirect"]:
                #pull method download file
                is_bundle = False
                if objectxmpp.back_to_deploy:
                    main_session = next(iter(objectxmpp.back_to_deploy))
                    bundle_package = objectxmpp.back_to_deploy[main_session]['Dependency'][0]
                    if ('hash_info' in objectxmpp.back_to_deploy[main_session]['packagelist'][bundle_package]['descriptor']['info'] and objectxmpp.back_to_deploy[main_session]['packagelist'][bundle_package]['descriptor']['info']['hash_info']['url'] != ""):
                        is_bundle = True


                if data['methodetransfert'] in ["pullcurl"]:
                    if (is_bundle or ('hash_info' in data['descriptor']['info'] and data['descriptor']['info']['hash_info']['url'] != "")):

                        logger.debug("----------Download file using CDN----------")

                        if objectxmpp.back_to_deploy:
                            if not 'hash_info' in data['descriptor']['info']:
                                data['descriptor']['info']['hash_info'] = objectxmpp.back_to_deploy[main_session]['packagelist'][bundle_package]['descriptor']['info']['hash_info']

                        recupfile = recuperefilecdn(datasend,
                                                    objectxmpp,
                                                    sessionid)
                    else:
                        recupfile = recuperefile(datasend,
                                                objectxmpp,
                                                data['ippackageserver'],
                                                data['portpackageserver'],
                                                sessionid)
                elif data['methodetransfert'] in ["pulldirect"]:
                    #implemente pull direct en rsync
                    recupfile = pull_package_transfert_rsync(datasend,
                                                             objectxmpp,
                                                             data['ippackageserver'],
                                                             sessionid,
                                                             cmdmode="rsync")
                if not recupfile:
                    logger.debug("Error Pull method transfert file")
                    datasend = {'action': "result" + action,
                                'sessionid': sessionid,
                                'data': data,
                                'ret': -1,
                                'base64': False
                                }
                    objectxmpp.send_message(mto=data['jidmaster'],
                                            mbody=json.dumps(datasend),
                                            mtype='chat')
                    datasend['data']['action'] = datasend['action']
                    datasend['action'] = "xmpplog"
                    datasend['data']['ret'] = -1
                    datasend['data']['sessionid'] = sessionid
                    objectxmpp.send_message(mto=objectxmpp.sub_logger,
                                            mbody=json.dumps(datasend),
                                            mtype='chat')
                    objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Terminate | Notify",
                                       date=None,
                                       fromuser="AM %s" % strjidagent,
                                       touser="")
                    #signalendsessionforARS(data , objectxmpp, sessionid, error = True)

                    # termine sesion on error
                    # clean session
                    objectxmpp.session.clearnoevent(sessionid)
                    # clean if not session
                    utils.cleanbacktodeploy(objectxmpp)
                    return
                else:
                    # Pull transfer complete
                    # send message to master for updatenbdeploy
                    datasend1 = {'action': "updatenbdeploy",
                                 'sessionid': sessionid,
                                 'data': data['advanced'],
                                 'ret': 1,
                                 'base64': False}
                    # send sessionid message to master with cmdid files installed
                    # update base has_login_command count_deploy_progress
                    objectxmpp.send_message(mto=data['jidmaster'],
                                            mbody=json.dumps(datasend1),
                                            mtype='chat')

            if 'advanced' not in datasend['data']:
                datasend['data']['advanced'] = {}
                datasend['data']['advanced']['exec'] = True

            if datasend['data']['advanced']['exec'] is True or 'advanced' not in datasend['data']:
                # deploy directly
                datasend['data']['advanced']['scheduling'] = False
                initialisesequence(datasend, objectxmpp, sessionid)
            else:
                # schedule deployment
                objectxmpp.xmpplog('Package deployment paused : %s' % data['name'],
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Notify",
                                   date=None,
                                   fromuser="AM %s" % strjidagent,
                                   touser="")
                datasend['data']['advanced']['scheduling'] = True
                objectxmpp.Deploybasesched.set_sesionscheduler(sessionid,json.dumps(datasend))
        else:
            objectxmpp.session.sessionsetdata(sessionid, datasend)  # save data in session
            grafcetdeploy.grafcet(objectxmpp, datasend)  # grafcet will use the session
            logger.debug("outing graphcet phase1")
    else:
        logger.debug("###################################################")
        logger.debug("##############AGENT RELAY SERVER###################")
        logger.debug("###################################################")
        if 'advanced' in data and 'paramdeploy' in data['advanced'] and 'section' in data['advanced']['paramdeploy'] and \
            data['advanced']['paramdeploy']['section'] in ['update','install','uninstall']:
            # priorite avanced selection
            pass
        else:
            # paramdeploy pas definie au lancement
            if 'descriptor' in data and \
                'info' in data['descriptor'] and \
                'type_section' in data['descriptor']['info']:
                if data['descriptor']['info']["type_section"].lower() in ['update','install','uninstall'] and \
                    'advanced' in data:
                    if 'paramdeploy' not in data['advanced']:
                        data['advanced']['paramdeploy']= {"section" : data['descriptor']['info']["type_section"].lower()}
                    else:
                        data['advanced']['paramdeploy']['section'] = data['descriptor']['info']["type_section"].lower()
        try:
            objectxmpp.reversedelpoy  # reversedelpoy add port for reverse ssh, used for del reverse
        except AttributeError:
            objectxmpp.reversedelpoy={}

        # START QUICK DEPLOY###########################################
        # self.mutex
        #logger.debug("%s"%json.dumps(data, indent=4))
        namefolder = None
        msgdeploy=[]


        if hasattr(objectxmpp.config, 'cdn_enable') and bool(strtobool(objectxmpp.config.cdn_enable)) is True:
            data['methodetransfert'] = 'pullcurl'
            data['descriptor']['info']['methodetransfert'] = 'pullcurl'
            url = objectxmpp.config.cdn_baseurl
            if url[-1] != '/':
                url = url + "/"

            token = objectxmpp.config.cdn_token
            data['descriptor']['info']['hash_info'] = {}
            data['descriptor']['info']['hash_info']['url'] = url
            data['descriptor']['info']['hash_info']['token'] = token

            if not 'hash' in data:
                if not 'packageUuid' in data:
                    package_uuid = data['name']
                else:
                    package_uuid = data['packageUuid']

                if hasattr(objectxmpp.config, 'cdn_hashing_algo'):
                    hash_algo = objectxmpp.config.cdn_hashing_algo
                else:
                    hash_algo = 'SHA256'

                if ('localisation_server' in data['descriptor']['info'] and data['descriptor']['info']['localisation_server'] != ""):
                    localisation_server = data['descriptor']['info']['localisation_server']
                elif ('previous_localisation_server' in data['descriptor']['info'] and data['descriptor']['info']['previous_localisation_server'] != ""):
                    localisation_server = data['descriptor']['info']['previous_localisation_server']

                hashFolder = os.path.join("/var", "lib", "pulse2", "packages", "hash", localisation_server)
                if os.path.exists(os.path.join(hashFolder, package_uuid + ".hash")):
                    data['hash'] = {'glaobal': file_get_contents(os.path.join(hashFolder, package_uuid + ".hash")), 'type': hash_algo}
            
            objectxmpp.xmpplog('Transfer Method is %s' % data['methodetransfert'],
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Transfer | Notify",
                                       date=None,
                                       fromuser=data['login'],
                                       touser="")

        if 'descriptor' in data and 'advanced' not in data:
            logger.debug("DEPLOYMENT ABORTED: ADVANCED DESCRIPTOR MISSING")
            objectxmpp.xmpplog('<span class="log_err">Deployment aborted: section key "avanced" missing</span>',
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               how="",
                               why="",
                               module="Deployment | Error",
                               date=None,
                               fromuser="AM %s" % strjidagent,
                               touser="")
            objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               how="",
                               why="",
                               module="Deployment | Terminate | Notify",
                               date=None,
                               fromuser="AM %s" % strjidagent,
                               touser="")
            objectxmpp.session.clearnoevent(sessionid)
            utils.cleanbacktodeploy(objectxmpp)

            datalog = {'action': "result%s" % action,
                       'sessionid': sessionid,
                       'ret': 255,
                       'base64': False,
                       'data': data
                      }
            objectxmpp.send_message(mto="master@pulse/MASTER",
                                    mbody=json.dumps(datalog),
                                    mtype='chat')
            datalog['data']['action'] = datalog['action']
            datalog['action'] = "xmpplog"
            datalog['data']['ret'] = 255
            datalog['data']['sessionid'] = sessionid
            objectxmpp.send_message(mto=objectxmpp.sub_logger,
                                    mbody=json.dumps(datalog),
                                    mtype='chat')
            if objectxmpp.session.isexist(sessionid):
                objectxmpp.session.clearnoevent(sessionid)
            return

        if objectxmpp.config.max_size_stanza_xmpp != 0:
            if 'descriptor' in data and \
                'info' in data['descriptor'] and \
                    'packageUuid' in data['descriptor']['info']:
                # Generate package if possible
                namefolder = data['descriptor']['info']['packageUuid']
            elif 'path'  in data:
                namefolder = os.path.basename(data['path'])

            if namefolder is not None:
                folder = os.path.join(managepackage.managepackage.packagedir(), namefolder)
                pathaqpackage = os.path.join(utils._path_packagequickaction(), namefolder)
                pathxmpppackage = "%s.xmpp" % pathaqpackage
                if not os.path.exists(pathxmpppackage) or \
                    (os.path.exists(pathxmpppackage) and \
                        int(time.time()- os.stat(pathxmpppackage).st_mtime) < 360):
                    try:
                        objectxmpp.mutex.acquire(1)
                        utils.qdeploy_generate(folder, objectxmpp.config.max_size_stanza_xmpp)
                    finally:
                        objectxmpp.mutex.release()
                # objectxmpp.nbconcurrentquickdeployments = 0   # compteur le nombre de deployement
                # if package exists, we can run deployment
                if os.path.exists("%s.xmpp" % pathaqpackage):
                    msgdeploy.append("Adding to quick deployment queue")
                    txt = "Transferring quick deployment package %s to %s" % (namefolder,
                                                                              data['jidmachine'])
                    msgdeploy.append(txt)
                    for i in msgdeploy:
                        objectxmpp.xmpplog(i,
                                           type='deploy',
                                           sessionname=sessionid,
                                           priority=-1,
                                           action="xmpplog",
                                           who=strjidagent,
                                           module="Deployment | Qdeploy | Notify",
                                           date=None,
                                           fromuser=data['login'])
                    msgquickstr = utils.get_message_xmpp_quick_deploy(folder, sessionid)
                    msgstruct=json.loads(msgquickstr)
                    msgstruct['data']['descriptor'] = data
                    #save pakage
                    if len(objectxmpp.concurrentquickdeployments) >=  objectxmpp.config.nbconcurrentquickdeployments:
                        # save deploy
                        namef=data['jidmachine'].split("/")[0]
                        filejson = os.path.join(utils._path_packagequickaction(),
                                            "%s@_@_@%s@_@_@.QDeploy"%(sessionid, namef))

                        with open(filejson, "w") as file:
                            json.dump(msgstruct, file)
                        objectxmpp.session.createsessiondatainfo(sessionid,
                                                                 datasession=data,
                                                                 timevalid=180)
                        res = utils.simplecommand("ls %s | wc -l" % os.path.join(utils._path_packagequickaction(), "*.QDeploy"))
                        if res['code'] == 0:
                            nbpool = res['result']
                        else:
                            nbpool = "????"
                        objectxmpp.xmpplog("Adding deployment %s to queue %s : %s" % (sessionid,
                                                                                      str(objectxmpp.boundjid.bare),
                                                                                      nbpool),
                                           type='deploy',
                                           sessionname=sessionid,
                                           priority=-1,
                                           action="xmpplog",
                                           who=strjidagent,
                                           module="Deployment | Qdeploy | Notify",
                                           date=None,
                                           fromuser=data['login'])
                        return
                    else:
                        try:
                            objectxmpp.mutex.acquire()
                            objectxmpp.concurrentquickdeployments[sessionid] = time.time()
                        finally:
                            objectxmpp.mutex.release()
                        objectxmpp.xmpplog("Quick deployment %s resource status: %s/%s" % (sessionid,
                                                                                           len(objectxmpp.concurrentquickdeployments),
                                                                                           objectxmpp.config.nbconcurrentquickdeployments),
                                           type='deploy',
                                           sessionname=sessionid,
                                           priority=-1,
                                           action="xmpplog",
                                           who=strjidagent,
                                           module="Deployment | Qdeploy | Notify",
                                           date=None,
                                           fromuser=data['login'])
                        # on lance le deployement
                        objectxmpp.send_message(mto=data['jidmachine'],
                                                mbody=json.dumps(msgstruct),
                                                mtype='chat')
                        objectxmpp.session.createsessiondatainfo(sessionid,
                                                                 datasession=data,
                                                                 timevalid=180)

                        logger.debug("List of concurrent deployments: %s" % json.dumps(objectxmpp.concurrentquickdeployments,
                                                                                       indent=4))
                        return
            # END QUICK DEPLOY###########################################
        # nota doc
        # a la réception d'un descripteur de deploiement, si plusieurs ARS sont dans le cluster,
        # on détermine quel ARS doit faire le deploiement. le descripteur est alors redirigé vers ARS qui doit deployé.
        # le descripteur transmit a alors une clef cluster avec comme valeur le (jid de ARS) qui soustraite le déploiement.
        # ARS qui recois ce descripteur assure le déploiement.



        # qui deploy dans le cluster.
        # Pour déterminer ARS qui deploye dans le cluster, on choisie ARS avec le plus petit coefficient de charge.
        # le coefficient de charge de deploiement de chaque ARS est connu par tout les ARS du cluster.
        # a la prise en compte d'un deploiement, ce coefficient  de charge est modifier,
        # alors tous les autre ARS du cluster recoive une notification permettant de tenir à jour ce coefficient.

        # Ce qui definie la charge d'un aRs, c'est le nombre de deploiement en cours( transfert de fichier non fait ou non terminer.)
        # si le transfert de fichiers est fait et terminé , alors ce deploiement n'est plus totalisé comme une charge pour ARS.
        # donc le coefficient de charge est diminué une fois un transfert de fichier terminé.
        # alors tous les autre ARS du cluster recoive une notification permettant de tenir à jour ce coefficient.

        # consernant les deploiement avec dépendances, tous les deployement des packages sont effectué par un meme ARS.


        # autre prise ne compte de charge d'un cluster.
        # on peut avoir une demande tres importantes de deploiements demandé a sur un ARS, meme au sein d'un cluster.
        # On a donc besoin d'un systeme de lissage de la charge ponctuel, pour que celle-ci soit dilué dans le temps.
        # pour cela, on définie un nombre maximun de deploiement simultané.
        # les deploiement sont empilés dans une pile LILO, puis dépilé est deployé pour avoir toujour une charge inférieur au nombre de deploiement simultanée demandé.
        # on utilisera une base non sql pour conservé les descripteurs en attente de deploiement.
        # ainsi on assurera une persistence en cas d'arrêt de ARS. les deploiements encore dans la base seront
        # effectués a la remise en fonction de ARS.
        #initialise charge_apparente_cluster si non initialiser
        if "login" not in data:
            data['login'] = ""
        add_chargeapparente(objectxmpp, strjidagent)
        clear_chargeapparente(objectxmpp)

        # if the advanced spooling parameter is set,
        # then it overrides the one defined in the package descriptor info session.
        if 'advanced' in data and 'spooling' in data['advanced']:
            prioritylist = ["high", "ordinary"]
            if data['advanced']['spooling'] in prioritylist :
                #limit_rate_ko in avansed deploy
                data['descriptor']['info']['spooling'] = str(data['advanced']['spooling'])
                data['advanced'].pop('spooling')
                objectxmpp.xmpplog('Deployment priority applied : %s' % data['descriptor']['info']['spooling'],
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Transfer | Notify",
                                   date=None,
                                   fromuser=data['login'],
                                   touser="")
        # RECEPTION message deploy
        if not ('step' in data or 'differed' in data) :
            # soon, there will also be sustitutes who can launch deployments.
            list_of_agents_who_can_lunch_deployment = ["master@pulse/MASTER"]
            if message['from'] in list_of_agents_who_can_lunch_deployment:
                objectxmpp.sessionaccumulator[sessionid] = time.time()
                # the deployment message comes from the master gold deployment agent.
                data['resource'] = False
                if 'cluster' not in data and len(objectxmpp.jidclusterlistrelayservers) > 0:
                    # determination of ARS that deploy
                    data['cluster'] = strjidagent
                    logger.debug("list ARS concurent : %s"%objectxmpp.jidclusterlistrelayservers)

                    levelchoisie = objectxmpp.levelcharge['charge'] +\
                                    objectxmpp.charge_apparente_cluster[strjidagent]['charge']
                    arsselection = str(strjidagent)
                    # on clear all apparent loads of more than 5 seconds
                    for ars in objectxmpp.jidclusterlistrelayservers:
                        if ars not in objectxmpp.charge_apparente_cluster:
                            add_chargeapparente(objectxmpp, ars)
                        charge = objectxmpp.jidclusterlistrelayservers[ars]['chargenumber'] +\
                                 objectxmpp.charge_apparente_cluster[ars]['charge']
                        if charge < levelchoisie:
                            levelchoisie = objectxmpp.jidclusterlistrelayservers[ars]['chargenumber']
                            arsselection = str(ars)
                    if arsselection != strjidagent:
                        logger.debug("Charge ARS ( %s ) is %s" % (strjidagent, objectxmpp.levelcharge['charge']))
                        logger.debug("DISPACHE VERS AUTRE ARS POUR LE DEPLOIEMENT : %s (charge level distant is : %s) " % (arsselection, levelchoisie))
                    # modify descriptor for new ARS
                    data['jidrelay'] = str(arsselection)
                    data['iprelay'] = objectxmpp.infomain['packageserver']['public_ip']
                    data['descriptor']['jidrelay'] = str(arsselection)
                    data['descriptor']['iprelay'] = objectxmpp.infomain['packageserver']['public_ip']
                    data['descriptor']['portpackageserver'] = objectxmpp.infomain['packageserver']['port']
                    data['ippackageserver'] = objectxmpp.infomain['packageserver']['public_ip']
                    data['portpackageserver'] = objectxmpp.infomain['packageserver']['port']
                    # prepare msg pour ARS choisie pour faire le deployment avec nouveau descripteur
                    datasend = {'action': action,
                                'sessionid': sessionid,
                                'data': data,
                                'ret': 0,
                                'base64': False
                                }
                    objectxmpp.send_message(mto=arsselection,
                                            mbody=json.dumps(datasend),
                                            mtype='chat')

                    if arsselection not in objectxmpp.charge_apparente_cluster:
                        add_chargeapparente(objectxmpp, arsselection)
                    q=time.time()
                    clear_chargeapparente(objectxmpp)
                    objectxmpp.charge_apparente_cluster[arsselection]['charge'] += 1
                    objectxmpp.charge_apparente_cluster[arsselection]['time'] = q
                    return
                else:
                    if 'cluster' not in data:
                        data['cluster'] = strjidagent
                        data['resource'] = False

                if 'cluster' in data and data['cluster'] != strjidagent:
                    logger.debug("Cluster [ARS %s delegating deployment to ARS %s]" % (data['cluster'], strjidagent))
                    #waitt master log start deploy
                    time.sleep(2)
                    objectxmpp.xmpplog('ARS %s delegating deployment to ARS %s' % (data['cluster'], strjidagent),
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Cluster | Notify",
                                       date=None,
                                       fromuser=data['login'],
                                       touser="")
                try:
                    if not objectxmpp.session.isexist(sessionid):
                        logger.debug("creation session %s" % sessionid)
                        data['pushinit'] = False
                        objectxmpp.session.createsessiondatainfo(sessionid,
                                                                 datasession=data,
                                                                 timevalid=180)

                    q=time.time()
                    # The rest of the treatment is difered, to allow the resources taken to be made to be contabilized.
                    for sesssionindex in objectxmpp.sessionaccumulator.copy():
                        if (q - objectxmpp.sessionaccumulator[sesssionindex]) > 10:
                            del objectxmpp.sessionaccumulator[sesssionindex]
                    if len(objectxmpp.sessionaccumulator) > objectxmpp.config.concurrentdeployments or \
                        len(objectxmpp.levelcharge['machinelist']) > objectxmpp.config.concurrentdeployments:
                        maxval = maximum(len(objectxmpp.levelcharge['machinelist']),len(objectxmpp.sessionaccumulator))
                        objectxmpp.xmpplog("<span class='log_warn'>"\
                                           "Spooling resource %s > %s configured</span>" % (maxval,
                                                                                            objectxmpp.config.concurrentdeployments),
                                           type='deploy',
                                           sessionname=sessionid,
                                           priority=-1,
                                           action="xmpplog",
                                           who=strjidagent,
                                           how="",
                                           why="",
                                           module="Deployment | Transfer | Notify",
                                           date=None,
                                           fromuser=data['login'],
                                           touser="")
                        data["differed"] = True
                        data["sessionid"] = sessionid
                        data["action"] = action
                        try:
                            del data["descriptor"]["metaparameter"]
                        except  Exception as e:
                            logger.warning(str(e))
                            traceback.print_exc(file=sys.stdout)
                        msglevelspoolig = '<span class="log_warn">Spooling the deployment in queue</span>'
                        objectxmpp.xmpplog(msglevelspoolig,
                                           type='deploy',
                                           sessionname=sessionid,
                                           priority=-1,
                                           action="xmpplog",
                                           who=strjidagent,
                                           how="",
                                           why="",
                                           module="Deployment | Transfer | Notify",
                                           date=None,
                                           fromuser=data['login'],
                                           touser="")
                        if objectxmpp.session.isexist(sessionid) and 'descriptor' not in data :
                            objsession = objectxmpp.session.sessionfromsessiondata(sessionid)
                            data_in_session = objsession.getdatasession()
                            data_in_session['sessionid'] = sessionid
                            data_in_session['from'] = str(message['from'])
                            data_in_session['action'] = str(action)
                            data = data_in_session

                        if 'spooling' in data["descriptor"]["info"]\
                            and data["descriptor"]["info"]['spooling'] == 'high':
                            objectxmpp.managefifo.setfifo(data, 'high')
                            msglevelspoolig = '%s (high priority session %s)</span>'%(msglevelspoolig, sessionid)
                        else:
                            objectxmpp.managefifo.setfifo(data)
                            msglevelspoolig = '%s (ordinary priority session %s)</span>' % (msglevelspoolig, sessionid)
                        objectxmpp.xmpplog(msglevelspoolig,
                                           type='deploy',
                                           sessionname=sessionid,
                                           priority=-1,
                                           action="xmpplog",
                                           who=strjidagent,
                                           how="",
                                           why="",
                                           module="Deployment | Transfer | Notify",
                                           date=None,
                                           fromuser=data['login'],
                                           touser="")
                        return
                except Exception as e:
                    logger.debug("error setfifo : %s" % str(e))
                    logger.error("\n%s" % (traceback.format_exc()))
                    # if not return deploy continue
                    return

        # Start deploiement
        if 'differed' in data:
            removeresource(data, objectxmpp, sessionid)
            objectxmpp.xmpplog('Deployment %s launched in spooling mode' % sessionid,
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               how="",
                               why="",
                               module="Deployment | Transfer | Notify",
                               date=None,
                               fromuser=data['login'],
                               touser="")
            #objectxmpp.levelcharge = objectxmpp.levelcharge - 1
        if 'advanced' in data and 'limit_rate_ko' in data['advanced'] :
            if data['advanced']['limit_rate_ko'] != 0:
                #limit_rate_ko in avansed deploy
                data['descriptor']['info']['limit_rate_ko']= str(data['advanced']['limit_rate_ko'])
                objectxmpp.xmpplog('Advanced deployment transfer rate limit : %s' % data['descriptor']['info']['limit_rate_ko'],
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Transfer | Notify",
                                   date=None,
                                   fromuser=data['login'],
                                   touser="")
        #determine methode transfert
        if 'descriptor' in data and 'info' in data['descriptor'] and 'methodetransfert' in data['descriptor']['info']:
            data['methodetransfert'] = data['descriptor']['info']['methodetransfert']
        if 'descriptor' in data and 'info' in data['descriptor'] and 'limit_rate_ko' in data['descriptor']['info']:
            data['limit_rate_ko'] = data['descriptor']['info']['limit_rate_ko']


        if 'transfert' in data:
            if data['transfert'] is True:
                objectxmpp.xmpplog('File transfer is enabled',
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Transfer | Notify",
                                   date=None,
                                   fromuser=data['login'],
                                   touser="")
                if 'methodetransfert' in data:
                    objectxmpp.xmpplog('Transfer Method is %s' % data['methodetransfert'],
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Transfer | Notify",
                                       date=None,
                                       fromuser=data['login'],
                                       touser="")
            else:
                objectxmpp.xmpplog('File transfer is disabled',
                                   type='deploy',
                                   sessionname=sessionid,
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   how="",
                                   why="",
                                   module="Deployment | Transfer | Notify",
                                   date=None,
                                   fromuser=data['login'],
                                   touser="")
            #verify if possible methode of transfert.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                sock.connect((data['ipmachine'], Globaldata['port_local']))
            except socket.error:
                if 'transfert' in data  and data['transfert'] is True \
                        and 'methodetransfert' in data \
                            and not data['methodetransfert'] in ["pulldirect",
                                                                 "pullcurl",
                                                                 "pullrsync",
                                                                 "pullscp"]:
                    try:
                        if objectxmpp.config.pushsubstitutionmethod in ["pulldirect",
                                                                        "pullcurl",
                                                                        "pullrsync",
                                                                        "pullscp"]:
                            data['methodetransfert'] = objectxmpp.config.pushsubstitutionmethod
                        else:
                            data['methodetransfert'] = "pulldirect"
                            logger.warning("check typo parameters pushsubstitutionmethod conf file applicationdeploymentjson.ini")
                    except:
                        logger.warning("check parameters pushsubstitutionmethod")
                        data['methodetransfert'] = "pulldirect"
                    objectxmpp.xmpplog('<span class="log_warn">Push method impossible. Machine is either behind nat or SSH server is not running. Forcing %s method</span>' % data['methodetransfert'],
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       how="",
                                       why="",
                                       module="Deployment | Transfer | Notify",
                                       date=None,
                                       fromuser=data['login'],
                                       touser="")
            finally:
                sock.close()
        if 'transfert' in data \
            and data['transfert'] is True\
                and 'methodetransfert' in data\
                    and data['methodetransfert'] in ["pullcurl",
                                                     "pulldirect"]:
            if data['methodetransfert'] == "pulldirect":
                install_key_by_iq(objectxmpp, data['jidmachine'], sessionid, strjidagent)
            # le transfert pull direct ou pullcurl est confie a l'agent machine.
            transfertdeploy = {'action': action,
                               'sessionid': sessionid,
                               'data': data,
                               'ret': 0,
                               'base64': False}
            # remote client use port for transfert  pull direct
            transfertdeploy['data']['portreversessh']=objectxmpp.config.reverseserver_ssh_port
            objectxmpp.send_message(mto=data['jidmachine'],
                                    mbody=json.dumps(transfertdeploy),
                                    mtype='chat')
            if not objectxmpp.session.isexist(sessionid):
                logger.debug("creation session %s" % sessionid)
                objectxmpp.session.createsessiondatainfo(sessionid, datasession=transfertdeploy, timevalid=180)
            return

        if 'transfert' in data \
            and data['transfert'] is True\
                and 'methodetransfert' in data\
                    and data['methodetransfert'] in ["pullrsync", "pullscp"] \
                        and 'transfertpullrsync' not in data:
            data['transfertpullrsync'] = True
            install_key_by_iq(objectxmpp, data['jidmachine'], sessionid, strjidagent)
            # creation d'un reverce ssh
            remoteport = get_free_tcp_port()  # get port free
            data['remoteport'] = remoteport
            datareversessh = {'action': 'reverse_ssh_on',
                              'sessionid': sessionid,
                              'data': {'request': 'askinfo',
                                       'port': remoteport,
                                       'host': data['uuid'],
                                       'remoteport': Globaldata['port_local'],
                                       'reversetype': 'R',
                                       'options': 'createreversessh',
                                       'persistence': 'no'},
                              'ret': 0,
                              'base64': False}
            # prend en compte les reverses de deployement
            # conservation remote port for del reverse ssh after transfert
            objectxmpp.reversedelpoy[sessionid] = remoteport

            objectxmpp.send_message(mto=message['to'],
                                    mbody=json.dumps(datareversessh),
                                    mtype='chat')
            objectxmpp.xmpplog('Creation of reverse ssh tunnel (port %s->%s) from %s' % (Globaldata['port_local'],
                                                                                         remoteport,
                                                                                         str(objectxmpp.boundjid.bare)),
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               how="",
                               why="",
                               module="Deployment | Transfer | Notify",
                               date=None,
                               fromuser=data['login'],
                               touser="")
            timeoutmax = 20  # timeout 20 seconde
            cmdreverse = "netstat -van4 | grep %s" % remoteport
            timeattente = 1
            objectxmpp.xmpplog('Waiting mount of reverse ssh tunnel for port %s' % (remoteport),
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               module="Deployment | Transfer | Notify",
                               date=None,
                               fromuser=data['login'])
            while True:
                try:
                    time.sleep(1)
                    obcmd = utils.simplecommandstr(cmdreverse)
                    if obcmd['code'] == 0:
                        if str(remoteport) in obcmd['result']:
                            objectxmpp.xmpplog('Reverse ssh tunnel mounted after %s sec for port %s' % (timeattente, remoteport),
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               how="",
                                               why="",
                                               module="Deployment | Transfer | Notify",
                                               date=None,
                                               fromuser=data['login'],
                                               touser="")
                            break
                    if timeattente > timeoutmax:
                        objectxmpp.xmpplog('<span class="log_err">Timeout %s sec mounting reversessh for port %s</span>' % (timeattente, remoteport),
                                           type='deploy',
                                           sessionname=sessionid,
                                           priority=-1,
                                           action="xmpplog",
                                           who=strjidagent,
                                           how="",
                                           why="",
                                           module="Deployment | Transfer | Notify",
                                           date=None,
                                           fromuser=data['login'],
                                           touser="")
                        raise
                    timeattente = timeattente + 1
                except Exception:
                    cleandescriptor( data)
                    datalog = {'action': "result%s" % action,
                               'sessionid': sessionid,
                               'ret': 255,
                               'base64': False,
                               'data': data
                               }
                    objectxmpp.send_message(mto="master@pulse/MASTER",
                                            mbody=json.dumps(datalog),
                                            mtype='chat')
                    datalog['data']['action'] = datalog['action']
                    datalog['action'] = "xmpplog"
                    datalog['data']['ret'] = 255
                    datalog['data']['sessionid'] = sessionid
                    objectxmpp.send_message(mto=objectxmpp.sub_logger,
                                            mbody=json.dumps(datalog),
                                            mtype='chat')
                    #termine session a tester
                    #clean session
                    if objectxmpp.session.isexist(sessionid):
                        objectxmpp.session.clearnoevent(sessionid)
                    ARSremovereversessh(objectxmpp,
                                        strjidagent,
                                        sessionid,
                                        loginname="",
                                        message="Reverse ssh error")
                    return
        # Traitement mode push et les mode "pullrsync", "pullscp"
        # mode push ARS to AM
        # UPLOAD FILE PACKAGE to MACHINE, all dependency
        # We are in the case where it is necessary to install all the packages for the deployment, dependency included
        if ('pushinit' in data and data['pushinit'] is False)  or not objectxmpp.session.isexist(sessionid):
            data['pushinit'] = True
            objectxmpp.session.createsessiondatainfo(sessionid,  datasession = data, timevalid = 180)
            if 'methodetransfert' in data and data['methodetransfert'] == "pushrsync":
                # installkey sur agent machine authorized_keys
                install_key_by_iq(objectxmpp, data['jidmachine'], sessionid, strjidagent)
            # In push method you must know or install the packages on machine agent
            # In push mode, the packets are sent to a location depending on reception
            # one must make a request to AM to know or sent the files.
            # request message pacquage location
            # create a message with the deploy sessionid.
            # action will be a call to a plugin info request here the folder_packages
            # le resultat de cet appel est un appel a plugin_applicationdeploymentjson.py avec meme sessionid et info du directory
            # logger.debug("search directory pakage flolder from AM")
            askinfo(data['jidmachine'],
                    sessionid,
                    objectxmpp,
                    informationasking=['folders_packages', 'os', 'cpu_arch', 'sshd_on'],
                    replyaction=action)
        else:
            # The session exists
            logger.debug("THE SESSION EXISTS")
            objsession = objectxmpp.session.sessionfromsessiondata(sessionid)
            data_in_session = objsession.getdatasession()

            if 'step' not in data:
                logger.debug("STEP NOT")
                #if 'keyinstall' in data and data['keyinstall'] is True:
                # We manage the message condition installation key
                # logger.debug("keyinstall in true")
                # data_in_session['keyinstall'] = True
                # objsession.setdatasession(data_in_session)

                if 'actiontype' in data and data['actiontype'] == 'requestinfo':
                    if 'folders_packages' in data :
                        data_in_session['folders_packages'] = data['folders_packages']
                        logger.debug("folders_packages client machine %s" % data_in_session['folders_packages'])
                    if 'cpu_arch' in data:
                        data_in_session['cpu_arch'] = data['cpu_arch']
                        logger.debug("cpu architecture client machine %s" % data_in_session['cpu_arch'])
                    if 'os' in data:
                        data_in_session['os'] = data['os']
                        logger.debug("os client machine %s" % data_in_session['os'])
                        data_in_session['os_version'] = data['os_version']
                        #set  user ssh
                        data_in_session['userssh'] = "pulseuser"
                        if data_in_session['os'].startswith('linux'):
                            data_in_session['rsyncpath'] = "rsync"
                        elif data_in_session['os'].startswith('win'):
                            if data_in_session['cpu_arch'].endswith('64'):
                                data_in_session['rsyncpath'] = "C:\\\\Windows\\\\SysWOW64\\\\rsync.exe"
                            else:
                                data_in_session['rsyncpath'] = "C:\\\\Windows\\\\System32\\\\rsync.exe"
                        elif data_in_session['os'].startswith('darwin'):
                            data_in_session['rsyncpath'] = "rsync"
                    # information set in session data
                    objsession.setdatasession(data_in_session)

                # We verify that we have all the information for the deployment
                if 'folders_packages' not in data_in_session or 'os' not in data_in_session:
                    # termine deploy on error
                    # We do not know folders_packages
                    logger.debug("DEPLOYMENT ABORTED: FOLDERS_PACKAGE MISSING")
                    objectxmpp.xmpplog('<span class="log_err">Deployment error: The folders_packages is missing</span>',
                                       type='deploy',
                                       sessionname=sessionid,
                                       priority=0,
                                       action="xmpplog",
                                       who=strjidagent,
                                       module="Deployment | Error",
                                       date=None,
                                       fromuser=data_in_session['name'])
                    #termine session a tester

                    data_in_session['environ'] = {}
                    cleandescriptor(data_in_session)
                    datalog = {'action': "result%s" % action,
                               'sessionid': sessionid,
                               'ret': 255,
                               'base64': False,
                               'data': data_in_session
                               }
                    objectxmpp.send_message(mto="master@pulse/MASTER",
                                            mbody=json.dumps(datalog),
                                            mtype='chat')
                    datalog['data']['action'] = datalog['action']
                    datalog['action'] = "xmpplog"
                    datalog['data']['ret'] = 255
                    datalog['data']['sessionid'] = sessionid
                    objectxmpp.send_message(mto=objectxmpp.sub_logger,
                                            mbody=json.dumps(datalog),
                                            mtype='chat')
                    #termine session a tester
                    #clean session
                    if objectxmpp.session.isexist(sessionid):
                        objectxmpp.session.clearnoevent(sessionid)
                    ARSremovereversessh(objectxmpp,
                                        strjidagent,
                                        sessionid,
                                        loginname="",
                                        message="folders_package missing")
                    return

                    # if not 'folders_packages' in data_in_session or not 'keyinstall' in data_in_session:
                if 'folders_packages' not in data_in_session:
                    # If the 2 conditions are not yet satisfied:
                    # - Key public ARS installed on AM,
                    # - And return the path or install the packages.
                    # We leave and await message of the missing condition.
                    return

                # We have all the information we continue deploy
                # You have to prepare the transfer of packages.
                # You must have a list of all the packages to install.
                # Because pakages can have dependencies
                list_of_deployment_packages = managepackage.search_list_of_deployment_packages(data_in_session['path'].split('/')[-1]).search()
                #Install packages
                #logger.debug("#################LIST PACKAGE DEPLOY SESSION #######################")
                # saves the list of packages to be transferred in the session.
                data_in_session['transferfiles'] = [x for x in list(list_of_deployment_packages) if x != ""]
                objsession.setdatasession(data_in_session)
                ### this plugin will call itself itself is transfer each time a package from the list of packages to transfer.
                ### to make this call we prepare a message with the current session.
                ### on the message ['step'] of the message or resume processing.
                ### here data ['step'] = "transferfiles"
                logger.debug("Next step: transfer phase" )
                # call for aller step suivant transfert file
                msg_self_call = create_message_self_for_transfertfile(sessionid)
                objectxmpp.send_message(mto=strjidagent,
                                        mbody=json.dumps(msg_self_call),
                                        mtype='chat')
            else:
                ########## session transfer file ##########
                #analysis of the resume variable (step)
                if data['step'] == "transferfiles":
                    logger.debug("SESSION TRANSFERT PACKAGES" )

                    if 'transferfiles' in data_in_session and len ( data_in_session['transferfiles']) != 0:
                        uuidpackages = data_in_session['transferfiles'].pop(0)
                        pathin = managepackage.managepackage.getpathpackage(uuidpackages)
                        #This variable will be in the future used for the transferrt version of rsync files
                        #pathout = "%s/%s"%(data_in_session['folders_packages'],pathin.split('/')[-1])
                        # Update the session for the next call.
                        # The transferred package is excluded from the list of future packages to install
                        objsession.setdatasession(data_in_session)
                        logger.debug("SEND COMMANDE")
                        logger.debug("TRANSFERT PACKAGE from %s" % pathin)
                        #The rsync command will have this form
                        packuuid = os.path.basename(pathin)
                        if 'limit_rate_ko' in data_in_session and \
                            data_in_session['limit_rate_ko'] != "" and\
                                int(data_in_session['limit_rate_ko']) > 0:
                            cmdpre = "scp -C -r -l %s "%(int(data_in_session['limit_rate_ko']) * 8)
                            cmdrsync = "rsync -z --rsync-path=%s --bwlimit=%s "%(data_in_session['rsyncpath'],
                                                                                 int(data_in_session['limit_rate_ko']) * 8)

                            msg = "Transfer package %s to %s [transfer rate: %s ko]" % (data_in_session['name'],
                                                                                        data_in_session['jidmachine'],
                                                                                        data_in_session['limit_rate_ko'])
                        else:
                            cmdpre = "scp -C -r "
                            cmdrsync = "rsync -z --rsync-path=%s " % data_in_session['rsyncpath']
                            msg = "Transfer package %s to %s" % (data_in_session['name'], data_in_session['jidmachine'])

                        ipmachine = data_in_session['ipmachine']
                        if 'remoteport' not in data_in_session:
                            clientssshport = Globaldata['port_local']
                        else :
                            clientssshport = data_in_session['remoteport']
                            ipmachine = "localhost"

                        optionscp = "-o IdentityFile=/root/.ssh/id_rsa "\
                                    "-o StrictHostKeyChecking=no "\
                                    "-o UserKnownHostsFile=/dev/null "\
                                    "-o Batchmode=yes "\
                                    "-o PasswordAuthentication=no "\
                                    "-o ServerAliveInterval=5 "\
                                    "-o CheckHostIP=no "\
                                    "-o LogLevel=ERROR "\
                                    "-o ConnectTimeout=40 "\
                                    "-o Port=%s "\
                                    "%s %s@%s:\"\\\"%s\\\"\"" % (clientssshport,
                                                                 pathin,
                                                                 data_in_session['userssh'],
                                                                 ipmachine,
                                                                 data_in_session['folders_packages'])

                        if data_in_session['folders_packages'].lower().startswith('c:') or data_in_session['folders_packages'][1] == ":" :
                            pathnew =  data_in_session['folders_packages'][2:]
                            # cywin path
                            pathnew = "/cygdrive/c/" + pathnew.replace("\\","/") + "/" + packuuid + "/"
                            #compose name for rsync
                            listpath = pathnew.split("/")
                            p = []
                            for indexpath in listpath:
                                if " " in indexpath:
                                    p.append('"' + indexpath + '"')
                                else:
                                    p.append(indexpath)
                            pathnew = "/".join(p)
                        else:
                            pathnew = data_in_session['folders_packages'] + "/" + packuuid + "/"
                        pathnew = pathnew.replace("//","/")
                        optionrsync = " -e \"ssh -o IdentityFile=/root/.ssh/id_rsa "\
                                        "-o UserKnownHostsFile=/dev/null "\
                                        "-o StrictHostKeyChecking=no "\
                                        "-o Batchmode=yes "\
                                        "-o PasswordAuthentication=no "\
                                        "-o ServerAliveInterval=5 "\
                                        "-o CheckHostIP=no "\
                                        "-o LogLevel=ERROR "\
                                        "-o ConnectTimeout=40 "\
                                        "-o Port=%s\" "\
                                        "-av --chmod=777 %s/ %s@%s:'%s'" % (clientssshport,
                                                                            pathin,
                                                                            data_in_session['userssh'],
                                                                            ipmachine,
                                                                            pathnew)
                        cmdscp = cmdpre + optionscp
                        cmdrsync = cmdrsync + optionrsync
                        if not os.path.isdir(data_in_session['path']):
                            objectxmpp.xmpplog('<span class="log_err">Transfer error: Package Server does not have this package %s</span>' % data_in_session['path'],
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               module="Deployment | Error | Download | Transfer",
                                               date=None,
                                               fromuser=data_in_session['login'])
                            objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               module="Deployment | Terminate |Notify",
                                               date=None,
                                               fromuser="AM %s" % strjidagent)
                            data_in_session['environ'] = {}
                            cleandescriptor( data_in_session )
                            datalog = {
                                'action': "result%s"%action,
                                'sessionid': sessionid,
                                'ret': 255,
                                'base64': False,
                                'data': data_in_session
                            }
                            objectxmpp.send_message(mto="master@pulse/MASTER",
                                                    mbody=json.dumps(datalog),
                                                    mtype='chat')
                            datalog['data']['action']=datalog['action']
                            datalog['action']="xmpplog"
                            datalog['data']['ret'] = 255
                            datalog['data']['sessionid'] = sessionid
                            objectxmpp.send_message(   mto=objectxmpp.sub_logger,
                                                            mbody = json.dumps(datalog),
                                                            mtype = 'chat')
                            #termine session a tester
                            #clean session
                            if objectxmpp.session.isexist(sessionid):
                                objectxmpp.session.clearnoevent(sessionid)
                            ARSremovereversessh(objectxmpp,
                                                strjidagent,
                                                sessionid,
                                                loginname = "",
                                                message = "Package Server does not have this package")
                            return
                        #push transfert
                        try:
                            takeresource(data_in_session, objectxmpp, sessionid)
                            if hasattr(objectxmpp.config, 'pushmethod') and objectxmpp.config.pushmethod == "scp":
                                cmdexec = cmdscp
                            else:
                                objectxmpp.config.pushmethod = "rsync"
                                cmdexec = cmdrsync
                            logger.debug("tranfert cmd :\n %s" % cmdexec)
                            objectxmpp.xmpplog("Command : " + cmdexec,
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               how="",
                                               why="",
                                               module="Deployment | Error | Download | Transfer",
                                               date=None,
                                               fromuser=data_in_session['login'],
                                               touser="")
                            objectxmpp.xmpplog(msg,
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               how="",
                                               why="",
                                               module="Deployment | Error | Download | Transfer",
                                               date=None,
                                               fromuser=data_in_session['login'],
                                               touser="")
                            obcmd = utils.simplecommandstr(cmdexec)
                        finally:
                            time.sleep(2)
                            removeresource(data_in_session, objectxmpp, sessionid)

                        if obcmd['code'] != 0:
                            objectxmpp.xmpplog('<span class="log_err">%s Transfer error : %s </span>' % (objectxmpp.config.pushmethod, obcmd['result']),
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               how="",
                                               why="",
                                               module="Deployment | Error | Download | Transfer",
                                               date=None,
                                               fromuser=data_in_session['login'],
                                               touser="")
                            objectxmpp.xmpplog('<span class="log_warn">Make sure ssh server is running on the client machine</span>',
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               how="",
                                               why="",
                                               module="Deployment | Error | Download | Transfer",
                                               date=None,
                                               fromuser=data_in_session['login'],
                                               touser="")
                            objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               how="",
                                               why="",
                                               module="Deployment | Terminate |Notify",
                                               date=None,
                                               fromuser="AM %s" % strjidagent,
                                               touser="")
                            data_in_session['environ'] = {}
                            cleandescriptor( data_in_session )
                            datalog = {'action': "result%s" % action,
                                       'sessionid': sessionid,
                                       'ret': 255,
                                       'base64': False,
                                       'data': data_in_session
                                       }

                            objectxmpp.send_message(mto="master@pulse/MASTER",
                                                    mbody=json.dumps(datalog),
                                                    mtype='chat')
                            datalog['data']['action']=datalog['action']
                            datalog['action']="xmpplog"
                            datalog['data']['ret'] = 255
                            datalog['data']['sessionid'] = sessionid
                            objectxmpp.send_message(mto=objectxmpp.sub_logger,
                                                    mbody=json.dumps(datalog),
                                                    mtype='chat')
                            #termine session a tester
                            #clean session
                            if objectxmpp.session.isexist(sessionid):
                                objectxmpp.session.clearnoevent(sessionid)
                            ARSremovereversessh(objectxmpp,
                                                strjidagent,
                                                sessionid,
                                                loginname="",
                                                message="Error sending file via the established reverse ssh tunnel.")
                            return
                        else:
                            objectxmpp.xmpplog('Result : %s'\
                                               '\nTransfer %s ' % (objectxmpp.config.pushmethod,
                                                                   obcmd['result']),
                                               type='deploy',
                                               sessionname=sessionid,
                                               priority=-1,
                                               action="xmpplog",
                                               who=strjidagent,
                                               how="",
                                               why="",
                                               module="Deployment | Terminate |Notify",
                                               date=None,
                                               fromuser="ARS %s" % strjidagent,
                                               touser="")
                        logger.debug("CALL FOR NEXT PACKAGE")
                        # call for aller step suivant
                        objectxmpp.send_message(mto = strjidagent,
                                            mbody = json.dumps(create_message_self_for_transfertfile(sessionid)),
                                            mtype = 'chat')
                    else:
                        # Creation of the message from depoy to machine
                        logger.debug("APPEL PLUGIN FOR DEPLOY ON MACHINE")
                        #del reversessh
                        ARSremovereversessh(objectxmpp,
                                            strjidagent,
                                            sessionid,
                                            loginname=data_in_session['login'],
                                            message="")
                        transfertdeploy = {'action': action,
                                           'sessionid': sessionid,
                                           'data': data_in_session,
                                           'ret': 0,
                                           'base64': False
                                           }
                        #logger.debug(json.dumps(transfertdeploy, indent = 4))
                        objectxmpp.send_message(mto=data_in_session['jidmachine'],
                                                mbody=json.dumps(transfertdeploy),
                                                mtype='chat')
                        #transfert terminer update Has_login_command
                        datasend = {'action': "updatenbdeploy",
                                    'sessionid': sessionid,
                                    'data': data_in_session['advanced'],
                                    'ret': 1,
                                    'base64': False
                                    }
                        objectxmpp.send_message(mto=data_in_session['jidmaster'],
                                                mbody=json.dumps(datasend),
                                                mtype='chat')
                        if objectxmpp.session.isexist(sessionid):
                            objectxmpp.session.clearnoevent(sessionid)


# FUNCTIONS #############################

def maximum(x,y) :
    if x > y:
        return(x)
    else:
        return(y)

def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port

def clear_chargeapparente(objectxmpp):
    timechargeapparente = 3
    q = time.time()
    for ars in objectxmpp.charge_apparente_cluster.copy():
        if (q - objectxmpp.charge_apparente_cluster[ars]['time']) >= timechargeapparente:
            # il faut remettre la charge apparente a time.time
            objectxmpp.charge_apparente_cluster[ars]['time'] = q
            objectxmpp.charge_apparente_cluster[ars]['charge'] = 0

def add_chargeapparente(objectxmpp, ars):
    #create structure if not exist
    if ars not in objectxmpp.charge_apparente_cluster:
        objectxmpp.charge_apparente_cluster[ars] = {}
        objectxmpp.charge_apparente_cluster[ars]['charge'] = 0
        objectxmpp.charge_apparente_cluster[ars]['time'] = time.time()


def changown_dir_of_file(dest, nameuser=None):
    if nameuser is None:
        nameuser = "pulseuser"

    dest = os.path.dirname(dest)
    if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
        try:
            uid = pwd.getpwnam(nameuser).pw_uid
            gid = grp.getgrnam(nameuser).gr_gid
            os.chown(dest, uid, gid)
            for dirpath, dirnames, filenames in os.walk(dest):
                for dname in dirnames:
                    os.chown(os.path.join(dirpath, dname), uid, gid)
                for fname in filenames:
                    os.chown(os.path.join(dirpath, fname), uid, gid)
        except Exception as e:
            logger.error("%s changown_dir_of_file : %s" % (dest, str(e)))
    elif sys.platform.startswith('win'):
        try:
            check_output(["icacls",
                          utils.encode_strconsole(dest),
                          "/setowner",
                          utils.encode_strconsole(nameuser),
                          "/t"], stderr=STDOUT)

        except Exception as e:
            logger.error("\n%s"%(traceback.format_exc()))

def install_key_by_iq(objectxmpp, tomachine, sessionid, fromrelay):
    logger.debug("Install ARS key in authorized_keys on client machine")

    objectxmpp.xmpplog( "Install ARS key in authorized_keys on client machine",
                            type = 'deploy',
                            sessionname = sessionid,
                            priority = 0,
                            action = "xmpplog",
                            who = fromrelay,
                            module = "Deployment | Error",
                            date = None )

    # Make sure reversessh account and keys exist
    msg = []
    username = 'reversessh'
    result, msglog = utils.reversessh_useraccount_mustexist_on_relay(username)
    if result is False:
        logger.error(msglog)
    msg.append(msglog)
    result, msglog = utils.reversessh_keys_mustexist_on_relay(username)
    if result is False:
        logger.error(msglog)
    msg.append(msglog)
    # Write message to logger
    for line in msg:
        objectxmpp.xmpplog(line,
                           type = 'deploy',
                           sessionname = sessionid,
                           priority = 0,
                           action = "xmpplog",
                           who = fromrelay,
                           module = "Deployment | Install",
                           date = None )
    # Install keys on client
    keyreversessh = utils.get_relayserver_reversessh_idrsa(username)
    try:
        key = utils.get_relayserver_pubkey('root')
    except IOError as e:
        msg = []
        msg.append("The public key /root/.ssh/id_rsa.pub is missing on the ARS %s" % fromrelay)


        msg.append("<span class='log_warn'>Please verify that the key is present.</span>")
        msg.append("<span class='log_warn'>Trying to continue the deploiement</span>")
        for line in msg:
            objectxmpp.xmpplog( line,
                                type = 'deploy',
                                sessionname = sessionid,
                                priority = 0,
                                action = "xmpplog",
                                who = fromrelay,
                                module = "Deployment | Install",
                                date = None )
        return False
    time_out_install_key = 60
    resultiqstr = objectxmpp.iqsendpulse(tomachine,
                                         {"action": "keyinstall",
                                          "data": {"key": key,
                                                   "keyreverseprivatssh": keyreversessh,
                                                   "sessionid": sessionid,
                                                   "from" : fromrelay}
                                          },
                                         time_out_install_key)
    resultiq = json.loads(resultiqstr)
    msglogbool = False
    if 'ret' in resultiq and resultiq['ret'] != 0:
        logger.error("Install of relay server key %s on machine %s" % (fromrelay, tomachine))
        if  'data' in resultiq and 'msg_error' in resultiq['data']:
            logger.error("Error description : %s"%json.dumps(resultiq['data']['msg_error'], indent = 4))
            objectxmpp.xmpplog( "Error on machine %s"%resultiq['data']['msg_error'],
                            type = 'deploy',
                            sessionname = sessionid,
                            priority = 0,
                            action = "xmpplog",
                            who = fromrelay,
                            module = "Deployment | Error",
                            date = None )
        msglogbool = True
    if "err" in resultiq:
        logger.error("Install ARS key %s on machine %s timed out %s" % (fromrelay,
                                                                        tomachine,
                                                                        time_out_install_key))
        msglogbool = True
    if msglogbool:
        msgerror = "Check why we cannot install the ars %s " \
                "keys on the machine %s" % (fromrelay, tomachine)
        logger.error(msgerror)
        objectxmpp.xmpplog( msgerror,
                            type = 'deploy',
                            sessionname = sessionid,
                            priority = 0,
                            action = "xmpplog",
                            who = fromrelay,
                            module = "Deployment | Error",
                            date = None )
        objectxmpp.xmpplog( "<span class='log_warn'>Trying to continue deployment</span>",
                            type = 'deploy',
                            sessionname = sessionid,
                            priority = 0,
                            action = "xmpplog",
                            who = fromrelay,
                            module = "Deployment | Error",
                            date = None )

def cleandescriptor(datasend):

    if sys.platform.startswith('linux'):
        try:
            del datasend['descriptor']['win']
        except KeyError:
            pass
        try:
            del datasend['descriptor']['mac']
        except KeyError:
            pass
        try:
            datasend['descriptor']['sequence'] = datasend['descriptor']['linux']['sequence']
            del datasend['descriptor']['linux']
        except:
            return False

    elif sys.platform.startswith('win'):
        try:
            del datasend['descriptor']['linux']
        except KeyError:
            pass
        try:
            del datasend['descriptor']['mac']
        except KeyError:
            pass
        try:
            datasend['descriptor']['sequence'] = datasend['descriptor']['win']['sequence']
            #del datasend['descriptor']['win']['sequence']
            del datasend['descriptor']['win']
        except:
            return False
    elif sys.platform.startswith('darwin'):
        try:
            del datasend['descriptor']['linux']
        except KeyError:
            pass
        try:
            del datasend['descriptor']['win']
        except KeyError:
            pass
        try:
            datasend['descriptor']['sequence'] = datasend['descriptor']['mac']['sequence']
            #del datasend['descriptor']['Macos']['sequence']
            del datasend['descriptor']['mac']
        except:
            return False
    datasend['typeos'] = sys.platform
    return True

def create_message_self_for_transfertfile(sessionid):
    return  {
        'action': plugin['NAME'],
        'sessionid': sessionid,
        'data':{'step': "transferfiles"},
        'ret': 0,
        'base64': False}

def ARSremovereversessh(objectxmpp,
                        strjidagent,
                        sessionid,
                        loginname = "",
                        message = ""):
    try:
        objectxmpp.reversedelpoy # reversedelpoy add port for reverse ssh, used for del reverse
    except AttributeError:
        objectxmpp.reversedelpoy={}
    if not message.strip():
        msg = "<span class='log_ok'>Transfer complete</span>"
    else:
        msg = "<span class='log_err'>Transfer error: %s</span>"%message
    objectxmpp.xmpplog(msg,
                       type='deploy',
                       sessionname=sessionid,
                       priority=-1,
                       action="xmpplog",
                       who=strjidagent,
                       module="Deployment | Terminate |Notify",
                       date=None,
                       fromuser="ARS %s" % strjidagent)
    if sessionid in objectxmpp.reversedelpoy:
        remoteport = objectxmpp.reversedelpoy[sessionid]
        cmd = """kill -9 $(lsof -i -n | grep  reversessh| grep %s | awk '{print $2}' | sort | uniq)""" % remoteport
        utils.simplecommandstr(cmd)
        if sessionid in objectxmpp.reversedelpoy:
            del objectxmpp.reversedelpoy[sessionid]
        objectxmpp.xmpplog("Closing reverse ssh tunnel for remote port %s" % remoteport,
                           type='deploy',
                           sessionname=sessionid,
                           priority=-1,
                           action="xmpplog",
                           who=strjidagent,
                           module="Deployment | Error | Download | Transfer",
                           date=None,
                           fromuser=loginname,
                           touser="")

def askinfo(to, sessionid, objectxmpp, informationasking=[], replyaction=None,
            list_to_sender=[], step=None):
    ask = {'action': "requestinfo",
           'sessionid': sessionid,
           'data': {'actiontype': 'requestinfo'},
           'ret': 0,
           'base64': False}

    if replyaction is not None:
        ask['data']['actionasker'] = replyaction
    if len(list_to_sender) != 0:
        ask['data']['sender'] = list_to_sender
    if step is not None:
        ask['data']['step'] = step
    if len(informationasking) != 0:
        ask['data']['dataask'] = informationasking

    objectxmpp.send_message(mto=to,
                            mbody=json.dumps(ask),
                            mtype='chat')

def takeresource(datasend, objectxmpp, sessionid):
    datasendl = {}
    if 'data' not in datasend:
        datasendl['data'] = datasend
    else:
        datasendl = datasend

    logger.debug('Taking resource : %s'%datasendl['data']['jidrelay'])
    msgresource = {'action': "cluster",
                    'sessionid': sessionid,
                    'data':  {"subaction" : "takeresource",
                                "data" : {'user': datasendl['data']['advanced']['login'],
                                        'machinejid': datasendl['data']['jidmachine']
                                }
                    },
                    'ret': 0,
                    'base64': False}
    objectxmpp.send_message(mto = datasendl['data']['jidrelay'],
                            mbody = json.dumps(msgresource),
                            mtype = 'chat')
    objectxmpp.xmpplog('Taking resource : %s'%datasendl['data']['jidrelay'],
                       type = 'deploy',
                       sessionname = sessionid,
                       priority = -1,
                       action = "xmpplog",
                       who = objectxmpp.boundjid.bare,
                       module = "Deployment| Notify | Cluster",
                       date=None,
                       fromuser = datasendl['data']['advanced']['login'])
    return datasend

def removeresource(datasend, objectxmpp, sessionid):
    datasendl = {}
    if 'data' not in datasend:
        datasendl['data'] = datasend
    else:
        datasendl = datasend
    logger.debug('Restoring resource : %s'%datasendl['data']['jidrelay'])
    msgresource = {'action': "cluster",
                    'sessionid': sessionid,
                    'data':  { "subaction" : "removeresource",
                                "data" : {'user': datasendl['data']['advanced']['login'],
                                            'machinejid': datasendl['data']['jidmachine']
                                }
                    },
                    'ret': 0,
                    'base64': False}
    objectxmpp.send_message(mto = datasendl['data']['jidrelay'],
                            mbody = json.dumps(msgresource),
                            mtype = 'chat')
    objectxmpp.xmpplog('Restoring resource : %s'%datasendl['data']['jidrelay'],
                       type = 'deploy',
                       sessionname = sessionid,
                       priority = -1,
                       action = "xmpplog",
                       who = objectxmpp.boundjid.bare,
                       module = "Deployment| Notify | Cluster",
                       date=None,
                       fromuser = datasendl['data']['advanced']['login'])
    return datasend

def initialisesequence(datasend, objectxmpp, sessionid ):
    strjidagent = str(objectxmpp.boundjid.bare)
    datasend['data']['stepcurrent'] = 0 #step initial
    if not objectxmpp.session.isexist(sessionid):
        logger.debug("creation session %s"%sessionid)
        objectxmpp.session.createsessiondatainfo(sessionid,  datasession = datasend['data'], timevalid = 180)
        logger.debug("update object backtodeploy")
    logger.debug("start call grafcet (initiation)")
    objectxmpp.xmpplog('Starting package execution : %s' % datasend['data']['name'],
                       type='deploy',
                       sessionname=sessionid,
                       priority=-1,
                       action="xmpplog",
                       who=strjidagent,
                       module="Deployment| Notify | Execution | Scheduled",
                       date=None,
                       fromuser=datasend['data']['advanced']['login'])

    logger.debug("start call grafcet (initiation)")
    if 'data' in datasend and \
                'descriptor' in datasend['data'] and \
                'path' in datasend['data'] and \
                "info" in datasend['data']['descriptor'] and \
                "launcher" in  datasend['data']['descriptor']['info']:
        try:
            id_package = os.path.basename(datasend['data']['path'])
            if id_package != "":
                name = datasend['data']['name']
                commandlauncher = base64.b64decode(datasend['data']['descriptor']['info']['launcher'])
                objectxmpp.infolauncherkiook.set_cmd_launch(id_package, commandlauncher)
                #addition correspondance name et idpackage.
                if name != "":
                    objectxmpp.infolauncherkiook.set_ref_package_for_name(name, id_package)
                    objectxmpp.xmpplog("Launcher command for kiosk [%s] - [%s] -> [%s]" % (commandlauncher, name, id_package),
                                       type='deploy',
                                       sessionname=datasend['sessionid'],
                                       priority=-1,
                                       action="xmpplog",
                                       who=strjidagent,
                                       module="Deployment | Kiosk",
                                       date=None,
                                       fromuser=str(datasend['data']['advanced']['login']))
                else:
                    logger.warning("nanme missing for info launcher command of kiosk")
            else:
                logger.warning("id package missing for info launcher command of kiosk")
        except:
            logger.error("launcher command of kiosk")
            traceback.print_exc(file=sys.stdout)
    else:
        logger.warning("launcher command missing for kiosk")
    grafcetdeploy.grafcet(objectxmpp, datasend)
    logger.debug("outing graphcet end initiation")


def curlgetdownloadfile(destfile, urlfile, insecure=True, token=None, limit_rate_ko=None):
    # As long as the file is opened in binary mode, both Python 2 and Python 3
    # can write response body to it without decoding.
    with open(destfile, 'wb') as f:
        if token is not None:
            headers = ["X-Authorization: " + token]
        c = pycurl.Curl()
        urlfile = urlfile.replace(" ", "%20")
        c.setopt(c.URL, urlfile)
        c.setopt(c.WRITEDATA, f)
        c.setopt(pycurl.HTTPHEADER, headers)
        try:
            limit_rate_ko = int(limit_rate_ko)
        except:
            limit_rate_ko = 0

        if limit_rate_ko is not None and limit_rate_ko != '' and int(limit_rate_ko) > 0:
            # limit_rate_ko en octed in curl
            c.setopt(c.MAX_RECV_SPEED_LARGE, int(limit_rate_ko) * 1024)
        if insecure :
            # option equivalent a friser de --insecure
            c.setopt(pycurl.SSL_VERIFYPEER, 0)
            c.setopt(pycurl.SSL_VERIFYHOST, 0)
        c.perform()
        c.close()

def pull_package_transfert_rsync(datasend, objectxmpp, ippackage, sessionid, cmdmode="rsync"):
    """
            # call function from agent machine
    """
    logger.info("###################################################")
    logger.info("pull_package_transfert_rsync : " + cmdmode)
    logger.info("###################################################")
    scp_limit_rate_ko = ""
    rsync_limit_rate_ko = ""
    if 'limit_rate_ko' in datasend['data'] and \
                    datasend['data']['limit_rate_ko'] != "" and\
                        int(datasend['data']['limit_rate_ko']) > 0:
        scp_limit_rate_ko = " -l %s "%(int(datasend['data']['limit_rate_ko']) * 8)
        rsync_limit_rate_ko = " --bwlimit %s "%(int(datasend['data']['limit_rate_ko']))
    takeresource(datasend, objectxmpp, sessionid)
    strjidagent = str(objectxmpp.boundjid.bare)
    if sys.platform.startswith('win'):
        #for windows scp only
        cmdmode= "scp"
    try:
        packagename = os.path.basename(datasend['data']['pathpackageonmachine'])
        packagename1 = "/var/lib/pulse2/packages/%s" % packagename
        userpackage = "reversessh"
        remotesrc = """%s@%s:'%s' """ % (userpackage, ippackage, packagename1)
        execrsync = "rsync"
        execscp = "scp"
        error = False
        if sys.platform.startswith('linux'):
            path_key_priv =  os.path.join(os.path.expanduser('~pulseuser'), ".ssh", "id_rsa")
            #localdest = " '%s/%s'" % (managepackage.managepackage.packagedir(), packagename)
            localdest = " '%s'" % (managepackage.managepackage.packagedir())
        elif sys.platform.startswith('win'):
            try:
                win32net.NetUserGetInfo('','pulseuser',0)
                path_key_priv =  os.path.join(utils.getHomedrive(), ".ssh", "id_rsa")
            except:
                path_key_priv = os.path.join("c:\progra~1", "pulse", '.ssh', "id_rsa")
            localdest = " \"%s/%s\"" % (managepackage.managepackage.packagedir(), packagename)
            if platform.machine().endswith('64'):
                execrsync = "C:\\\\Windows\\\\SysWOW64\\\\rsync.exe"
            else:
                execrsync = "C:\\\\Windows\\\\System32\\\\rsync.exe"
            execscp = '"c:\progra~1\OpenSSH\scp.exe"'
        elif sys.platform.startswith('darwin'):
            path_key_priv =  os.path.join("/", "var", "root", ".ssh", "id_rsa")
            #localdest = " '%s/%s'" % (managepackage.managepackage.packagedir(), packagename)
            localdest = " '%s'" % (managepackage.managepackage.packagedir())
        else :
            return False

        cmdtransfert = "%s%s -C -r " % (scp_limit_rate_ko, execscp)

        cmd = """%s -P%s -o IdentityFile=%s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o Batchmode=yes -o PasswordAuthentication=no -o ServerAliveInterval=10 -o CheckHostIP=no -o LogLevel=ERROR -o ConnectTimeout=10 """ % (cmdtransfert, objectxmpp.config.reverseserver_ssh_port, path_key_priv)

        if sys.platform.startswith('win'):
            scp = str(os.path.join(os.environ["ProgramFiles"], "OpenSSH", "scp.exe"))
            cmd = """ "c:\progra~1\OpenSSH\scp.exe"%s -r -C -P%s "-o IdentityFile=%s" "-o UserKnownHostsFile=/dev/null" "-o StrictHostKeyChecking=no" "-o Batchmode=yes" "-o PasswordAuthentication=no" "-o ServerAliveInterval=10" "-o CheckHostIP=no" "-o LogLevel=ERROR" "-o ConnectTimeout=10" """ % (scp_limit_rate_ko, objectxmpp.config.reverseserver_ssh_port, path_key_priv)
        if cmdmode == "rsync":
            cmdtransfert =  " %s -L -z --rsync-path=rsync%s"%(execrsync, rsync_limit_rate_ko)
            cmd = """%s -e "ssh -P%s -o IdentityFile=%s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o Batchmode=yes -o PasswordAuthentication=no -o ServerAliveInterval=10 -o CheckHostIP=no -o LogLevel=ERROR -o ConnectTimeout=10" -av --chmod=777 """ % (cmdtransfert, objectxmpp.config.reverseserver_ssh_port, path_key_priv)

        cmdexec =  cmd + remotesrc + localdest

        objectxmpp.xmpplog("Client generated transfer command is : \n %s" % cmdexec,
                           type='deploy',
                           sessionname=datasend['sessionid'],
                           priority=-1,
                           action="xmpplog",
                           who=strjidagent,
                           module="Deployment | Download | Transfer",
                           date=None,
                           fromuser=datasend['data']['advanced']['login'])
        obj = utils.simplecommand(cmdexec)

        if obj['code'] != 0:
            objectxmpp.xmpplog("Transfer error: \n %s" % obj['result'],
                               type='deploy',
                               sessionname=datasend['sessionid'],
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               module="Deployment | Download | Transfer",
                               date=None,
                               fromuser=datasend['data']['advanced']['login'])
            error = True
            return False
        else:
            if len (obj['result']) > 0:
                msg = "<span class='log_warn'>Transfer warning:\n%s</span>" % obj['result']
            else:
                msg = "<span class='log_ok'>Transfer successful</span>"
            objectxmpp.xmpplog(msg,
                               type='deploy',
                               sessionname=datasend['sessionid'],
                               priority=-1,
                               action="xmpplog",
                               who=strjidagent,
                               module="Deployment | Download | Transfer",
                               date=None,
                               fromuser=datasend['data']['advanced']['login'])
        error = False
        return True
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
        error = True
        return False
    finally:
        removeresource(datasend, objectxmpp, sessionid)
        signalendsessionforARS(datasend, objectxmpp, sessionid, error=error)

def recuperefile(datasend, objectxmpp, ippackage, portpackage, sessionid):
    strjidagent = str(objectxmpp.boundjid.bare)
    if not os.path.isdir(datasend['data']['pathpackageonmachine']):
        os.makedirs(datasend['data']['pathpackageonmachine'], mode=0777)
    uuidpackage = datasend['data']['path'].split('/')[-1]
    curlurlbase = "https://%s:%s/mirror1_files/%s/" % (ippackage, portpackage, uuidpackage)
    takeresource(datasend, objectxmpp, sessionid)
    objectxmpp.xmpplog("Package server is %s" % curlurlbase,
                       type='deploy',
                       sessionname=datasend['sessionid'],
                       priority=-1,
                       action="xmpplog",
                       who=strjidagent,
                       module="Deployment | Download | Transfer",
                       date=None,
                       fromuser=datasend['data']['advanced']['login'])

    for filepackage in datasend['data']['packagefile']:
        if datasend['data']['methodetransfert'] == "pullcurl":
            dest = os.path.join(datasend['data']['pathpackageonmachine'], filepackage)
            urlfile = curlurlbase + filepackage

            logger.info("###################################################")
            logger.info("URL for downloading package using curl : " + urlfile)
            logger.info("###################################################")
            try:
                if 'limit_rate_ko' in datasend['data']['descriptor']['info'] and \
                                datasend['data']['descriptor']['info']['limit_rate_ko'] != "" and\
                                    int(datasend['data']['descriptor']['info']['limit_rate_ko'])> 0:
                    limit_rate_ko = datasend['data']['descriptor']['info']['limit_rate_ko']
                    msg = 'Downloading file : %s Package : %s [transfer rate %s ko]' % (filepackage, datasend['data']['name'], limit_rate_ko)
                else:
                    limit_rate_ko = ""
                    msg = 'Downloading file : %s Package : %s' % (filepackage, datasend['data']['name'])
                objectxmpp.xmpplog(msg,
                                   type='deploy',
                                   sessionname=datasend['sessionid'],
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   module="Deployment | Download | Transfer",
                                   date=None,
                                   fromuser=datasend['data']['advanced']['login'])
                curlgetdownloadfile(dest, urlfile, insecure=True, limit_rate_ko=limit_rate_ko)
                changown_dir_of_file(dest)  # owner pulseuser.
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                logger.debug(str(e))
                objectxmpp.xmpplog('<span class="log_err">Transfer error : curl download [%s] package file: %s</span>' % (curlurlbase, filepackage),
                                   type='deploy',
                                   sessionname=datasend['sessionid'],
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   module="Deployment | Download | Transfer | Notify | Error",
                                   date=None,
                                   fromuser=datasend['data']['name'])
                objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                   type='deploy',
                                   sessionname=datasend['sessionid'],
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   module="Deployment | Error | Terminate | Notify",
                                   date=None,
                                   fromuser=datasend['data']['name'])
                removeresource(datasend, objectxmpp, sessionid)
                signalendsessionforARS(datasend, objectxmpp, sessionid, error=True)
                return False
    removeresource(datasend, objectxmpp, sessionid)
    signalendsessionforARS(datasend, objectxmpp, sessionid, error=False)
    return True

def check_hash(objectxmpp, data):
    hash_type = data['hash']['type']
    dest = data['pathpackageonmachine']
    dest += "\\"
    concat_hash = ""

    if hasattr(objectxmpp.config, 'keyAES32'):
        salt = objectxmpp.config.keyAES32

    BLOCK_SIZE = 65535

    try:
        file_hash = hashlib.new(hash_type)
    except:
        logger.error("Wrong hash type")

    for file_package in sorted(data['packagefile']):
        with open(os.path.join(dest, file_package), "rb") as _file:
            try:
                file_hash = hashlib.new(hash_type)
            except:
                logging.error("Wrong hash type")
            file_block = _file.read(BLOCK_SIZE) # Read from the file. Take in the amount declared above
            while len(file_block) > 0:
                file_hash.update(file_block)
                file_block = _file.read(BLOCK_SIZE)
            
        concat_hash += file_hash.hexdigest()
    
    concat_hash += salt
    try:
        file_hash = hashlib.new(hash_type)
    except:
        logger.error("Wrong hash type")
    file_hash.update(concat_hash)
    concat_hash = file_hash.hexdigest()
    
    return concat_hash

def recuperefilecdn(datasend, objectxmpp, sessionid):
    strjidagent = str(objectxmpp.boundjid.bare)
    if not os.path.isdir(datasend['data']['pathpackageonmachine']):
        os.makedirs(datasend['data']['pathpackageonmachine'], mode=0777)
    
    uuidpackage = datasend['data']['path'].split('/')[-1]
    curlurlbase = datasend['data']['descriptor']['info']['hash_info']['url']
    takeresource(datasend, objectxmpp, sessionid)
    objectxmpp.xmpplog("Package server is %s" % curlurlbase,
                       type='deploy',
                       sessionname=datasend['sessionid'],
                       priority=-1,
                       action="xmpplog",
                       who=strjidagent,
                       module="Deployment | Download | Transfer",
                       date=None,
                       fromuser=datasend['data']['advanced']['login'])

    for filepackage in datasend['data']['packagefile']:
        if datasend['data']['methodetransfert'] == "pullcurl":
            dest = os.path.join(datasend['data']['pathpackageonmachine'], filepackage)

            packageUuid = str(datasend['data']['descriptor']['info']['packageUuid'])

            if ('localisation_server' in datasend['data']['descriptor']['info'] and datasend['data']['descriptor']['info']['localisation_server'] != ""):
                urlfile = str(curlurlbase) + str(datasend['data']['descriptor']['info']['localisation_server']) + "/" + packageUuid + "/" + str(filepackage)
            elif ('previous_localisation_server' in datasend['data']['descriptor']['info'] and datasend['data']['descriptor']['info']['previous_localisation_server'] != ""):
                urlfile = str(curlurlbase) + str(datasend['data']['descriptor']['info']['previous_localisation_server']) + "/" + packageUuid + "/" + str(filepackage)

            urlobject = urlparse(urlfile)
            urlfile = urlobject.scheme + '://' + urllib.quote(urlobject.netloc) + urllib.quote(urlobject.path)
            token = datasend['data']['descriptor']['info']['hash_info']['token']
            logger.debug("URL for downloading package using curl : " + urlfile)
            try:
                if 'limit_rate_ko' in datasend['data']['descriptor']['info'] and \
                                datasend['data']['descriptor']['info']['limit_rate_ko'] != "" and\
                                    int(datasend['data']['descriptor']['info']['limit_rate_ko'])> 0:
                    limit_rate_ko = datasend['data']['descriptor']['info']['limit_rate_ko']
                    try:
                        limit_rate_ko = int(limit_rate_ko)
                    except:
                        limit_rate_ko = 0
                    msg = 'Downloading file : %s Package : %s [transfer rate %s ko]' % (filepackage, datasend['data']['name'], limit_rate_ko)
                else:
                    limit_rate_ko = ""
                    msg = 'Downloading file : %s Package : %s' % (filepackage, datasend['data']['name'])
                objectxmpp.xmpplog(msg,
                                   type='deploy',
                                   sessionname=datasend['sessionid'],
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   module="Deployment | Download | Transfer",
                                   date=None,
                                   fromuser=datasend['data']['advanced']['login'])

                if token is not None:
                    headers = "X-Authorization: " + str(token)
                else:
                    headers = ""
                if limit_rate_ko == 0 or limit_rate_ko == "":
                    cmd = """curl -k -H \"%s\" %s -o \"%s\" """ % (headers, urlfile, dest)
                else:
                    cmd = """curl --limit-rate %s -k -H \"%s\" %s -o \"%s\" """ % (limit_rate_ko, headers, urlfile, dest)
                obj = utils.simplecommand(cmd)
                if obj['code'] != 0:
                    objectxmpp.xmpplog('<span class="log_err">Transfer error %s : curl download [%s] package file: %s\n %s</span>' % (obj['code'], curlurlbase, filepackage, obj['result']),
                                    type='deploy',
                                    sessionname=datasend['sessionid'],
                                    priority=-1,
                                    action="xmpplog",
                                    who=strjidagent,
                                    module="Deployment | Download | Transfer",
                                    date=None,
                                    fromuser=datasend['data']['advanced']['login'])
                    objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                    type='deploy',
                                    sessionname=datasend['sessionid'],
                                    priority=-1,
                                    action="xmpplog",
                                    who=strjidagent,
                                    module="Deployment | Error | Terminate | Notify",
                                    date=None,
                                    fromuser=datasend['data']['name'])
                    removeresource(datasend, objectxmpp, sessionid)
                    signalendsessionforARS(datasend, objectxmpp, sessionid, error=True)
                    return False
                else:
                    msg = "<span class='log_ok'>Transfer successful</span>"
                    objectxmpp.xmpplog(msg,
                                    type='deploy',
                                    sessionname=datasend['sessionid'],
                                    priority=-1,
                                    action="xmpplog",
                                    who=strjidagent,
                                    module="Deployment | Download | Transfer",
                                    date=None,
                                    fromuser=datasend['data']['advanced']['login'])
                changown_dir_of_file(dest)  # owner pulseuser.
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                logger.error('Traceback from downloading package via libcurl: %s' % str(e))
                objectxmpp.xmpplog('<span class="log_err">Transfer error : curl download [%s] package file: %s</span>' % (curlurlbase, filepackage),
                                   type='deploy',
                                   sessionname=datasend['sessionid'],
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   module="Deployment | Download | Transfer | Notify | Error",
                                   date=None,
                                   fromuser=datasend['data']['name'])
                objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                   type='deploy',
                                   sessionname=datasend['sessionid'],
                                   priority=-1,
                                   action="xmpplog",
                                   who=strjidagent,
                                   module="Deployment | Error | Terminate | Notify",
                                   date=None,
                                   fromuser=datasend['data']['name'])
                removeresource(datasend, objectxmpp, sessionid)
                signalendsessionforARS(datasend, objectxmpp, sessionid, error=True)
                return False
    _check_hash = check_hash(objectxmpp, datasend['data'])
    if _check_hash != datasend['data']['hash']['global']:
        shutil.rmtree(datasend['data']['pathpackageonmachine'])
        logger.error("HASH INVALID - ABORT DEPLOYMENT")
        objectxmpp.xmpplog('<span class="log_err">Package delayed : hash invalid</span>',
            type='deploy',
            sessionname=datasend['sessionid'],
            priority=-1,
            action="xmpplog",
            who=strjidagent,
            module="Deployment | Error | Terminate | Notify",
            date=None,
            fromuser=datasend['data']['name'])
        removeresource(datasend, objectxmpp, sessionid)
        signalendsessionforARS(datasend, objectxmpp, sessionid, error=True)
        return False
    removeresource(datasend, objectxmpp, sessionid)
    signalendsessionforARS(datasend, objectxmpp, sessionid, error=False)
    return True

def signalendsessionforARS(datasend, objectxmpp, sessionid, error=False):
    #termine sessionid sur ARS pour permettre autre deploiement
    try :
        msgsessionend = {'action': "resultapplicationdeploymentjson",
                         'sessionid': sessionid,
                         'data': datasend,
                         'ret': 255,
                         'base64': False
                         }
        if error is False:
            msgsessionend['ret'] = 0
        datasend['endsession'] = True
        objectxmpp.send_message(mto=datasend['data']['jidrelay'],
                                mbody=json.dumps(msgsessionend),
                                mtype='chat')
    except Exception as e:
        logger.debug(str(e))
        traceback.print_exc(file=sys.stdout)
