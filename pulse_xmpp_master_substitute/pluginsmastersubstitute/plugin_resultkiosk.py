# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


# A REFAIRE POUR LES SUBSTITUT.
# code commenter est a adapter.
import datetime
import time
import pytz
import json
import traceback
import sys
import logging
import os
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.kiosk import KioskDatabase
from lib.plugins.msc import MscDatabase
from lib.plugins.glpi import Glpi



logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "resultkiosk", "TYPE": "substitute"}  # fmt: skip


# if not fromplugin:
# send_message_to_machine(datas, jid, name_random(6, "initialisation_kiosk"))
# return datas


# def get_packages_for_machine(machine):
# """Get a list of the packages for the concerned machine.
# Param:
# machine : tuple of the machine datas
# Returns:
# list of the packages"""
# OUmachine = [
# machine["ad_ou_machine"].replace("\n", "").replace("\r", "").replace("@@", "/")
# ]
# OUuser = [
# machine["ad_ou_user"].replace("\n", "").replace("\r", "").replace("@@", "/")
# ]




## search packages for the applied profiles
# list_profile_packages = KioskDatabase().get_profile_list_for_OUList(tmp)
# if list_profile_packages is None:
## TODO
## linux and mac os does not have an Organization Unit.
## For mac os and linux, profile association will be done on the login name.
# return



## Create structuredatakiosk for initialization

# return structuredatakiosk



# Returns:
# TreeOU object which contains all the OUs.
# or
# returns False for some issues
# """

## Check the ldap config


# if kconfig.use_external_ldap is False:
# ous = XmppMasterDatabase().get_ou_list_from_machines()
# elif config.has_section("authentication_externalldap"):
# id = str(uuid.uuid4())
# file = "/tmp/ous-" + id

## Get the parameters from the config file

## Execute the command which get the OU list and write into the specified file

# os.system(command)

## Parse the file

## Parse the result for each lines



## Delete the file
# os.remove(file)
# else:
# return False


# return tree


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("#################################################")
    logger.debug(plugin)
    logger.debug(json.dumps(data, indent=4))
    logger.debug("#################################################")

    logger.debug(
        "A adapter pour python 3. le traitement n'est plus dans mmc mais dans le substitut master."
    )

    # if 'subaction' in data:
    # if data['subaction'] == 'initialization':
    # initialisekiosk(data, message, xmppobject)
    # elif data['subaction'] == 'launch':
    # deploypackage(data,  message, xmppobject, sessionid)
    # elif data['subaction'] == 'delete':
    # deploypackage(data,  message, xmppobject, sessionid)
    # elif data['subaction'] == 'install':
    # deploypackage(data,  message, xmppobject, sessionid)
    # elif data['subaction'] == 'update':
    # deploypackage(data,  message, xmppobject, sessionid)
    # elif data['subaction'] == 'presence':
    # machine =  XmppMasterDatabase().getMachinefromjid(message['from'])
    # if "id" in machine:
    # result = XmppMasterDatabase().updatemachine_kiosk_presence(machine['id'], data['value'])
    # elif data['subaction'] == 'ask':
    # machine = XmppMasterDatabase().getMachinefromjid(message['from'])
    # profiles = []
    # if machine is not None:
    # OUmachine = [machine['ad_ou_machine'].replace("\n",'').replace("\r",'').replace('@@','/')]
    # OUuser = [machine['ad_ou_user'].replace("\n", '').replace("\r", '').replace('@@','/')]
    # OU =  [elem for elem in set(OUmachine + OUuser) if elem != ""]
    # profiles = KioskDatabase().add_askacknowledge(OU, data['uuid'], data['askuser'])
    # else:
    # print "No subaction found"
    # else:
    # pass






# def initialisekiosk(data, message, xmppobject):
# machine = XmppMasterDatabase().getMachinefromjid(message['from'])
# if "userlist" and "oumachine" and "ouuser" in data:
# if len(data['userlist']) == 0:
# user = ""
# else:
# user = data['userlist'][0]
# print "call updatemachineAD"
# XmppMasterDatabase().updatemachineAD(machine['id'], user, data['oumachine'], data['ouuser'])






## Get the actual timestamp in utc format


# sent_datetime = datetime.datetime(date_list[0],
# date_list[1],
# date_list[2],
# date_list[3],
# date_list[4],
# 0, 0,
# pytz.UTC)
# install_date = utc2local(sent_datetime)
# else:
# install_date = current_date

# nameuser = "(kiosk):%s/%s"%(machine['lastuser'],machine['hostname'])
# if data['subaction'] == "install":
# section = '"section":"install"'
# elif data['subaction'] == "delete":
# section = '"section":"uninstall"'
# elif data['subaction'] == "update":
# section = '"section":"update"'
# else:
# section = '"section":"install"'

# package = json.loads(get_xmpp_package(data['uuid']))
# _section = section.split(":")[1]
# command = MscDatabase().createcommanddirectxmpp(data['uuid'],
#'',
# section,
#'malistetodolistfiles',
#'enable',
#'enable',
# install_date,
# install_date + datetime.timedelta(hours=1),
# nameuser,
# nameuser,
# package['info']['name']+' : '+_section,
# 60,
# 4,
# 0,
#'',
# None,
# None,
# None,
#'none',
#'active',
#'1',
# cmd_type=0)
# commandid = command.id
# commandstart = command.start_date
# commandstop = command.end_date
# jidrelay = machine['groupdeploy']
# uuidmachine = machine['uuid_inventorymachine']
# jidmachine = machine['jid']
# try:
# target = MscDatabase().xmpp_create_Target(uuidmachine, machine['hostname'])

# except Exception as e:
# print str(e)
# traceback.print_exc(file=sys.stdout)



## Write advanced parameter for the deployment



# descript = managepackage.loadjsonfile(os.path.join(path, 'xmppdeploy.json'))
# parsexmppjsonfile(os.path.join(path, 'xmppdeploy.json'))
# if descript is None:
# logger.error("deploy %s on %s  error : xmppdeploy.json missing" %
# (data['uuid'], machine['hostname']))
# return None
# objdeployadvanced = XmppMasterDatabase().datacmddeploy(commandid)
# if not objdeployadvanced:
# logger.error("The line has_login_command for the idcommand %s is missing" % commandid)
# logger.error("To solve this, please remove the group, and recreate it")
# datasend = {"name": name,
# "login": nameuser,
# "idcmd": commandid,
# "advanced": objdeployadvanced,
#'methodetransfert': 'pushrsync',
# "path": path,
# "packagefile": os.listdir(path),
# "jidrelay": jidrelay,
# "jidmachine": jidmachine,
# "jidmaster": xmppobject.boundjid.bare,
# "iprelay":  XmppMasterDatabase().ipserverARS(jidrelay)[0],
# "ippackageserver":  XmppMasterDatabase().ippackageserver(jidrelay)[0],
# "portpackageserver":  XmppMasterDatabase().portpackageserver(jidrelay)[0],
# "ipmachine": XmppMasterDatabase().ipfromjid(jidmachine)[0],
# "ipmaster": xmppobject.config.Server,
# "Dtypequery": "TQ",
# "Devent": "DEPLOYMENT START",
# "uuid": uuidmachine,
# "descriptor": descript,
# "transfert": True
# }
## run deploy

# sessionid = xmppobject.send_session_command(jidrelay,
# "applicationdeploymentjson",
# datasend,
# datasession=None,
# encodebase64=False)
## add deploy in table.
# XmppMasterDatabase().adddeploy(commandid,
# machine['jid'],  # jidmachine
# machine['groupdeploy'],  # jidrelay,
# machine['hostname'],  # host,
# machine['uuid_inventorymachine'],  # inventoryuuid,
# data['uuid'],  # uuidpackage,
#'DEPLOYMENT START',  # state,
# sessionid,  # id session,
# nameuser,  # user
# nameuser,  # login
# name + " " + \
# commandstart.strftime("%Y/%m/%d/ %H:%M:%S"),  # title,
# "",  # group_uuid
# commandstart,  # startcmd
# commandstop,  # endcmd
# machine['macaddress'])

## Convert install_date to timestamp and send it to logs
