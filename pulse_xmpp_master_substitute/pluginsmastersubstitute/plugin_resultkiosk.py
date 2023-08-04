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

# from managepackage import managepackage

# from lib.utils import name_random, file_put_contents, file_get_contents, utc2local
# import re
# from mmc.plugins.kiosk import handlerkioskpresence
# from mmc.plugins.pkgs import get_xmpp_package

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "resultkiosk", "TYPE": "substitute"}

# def handlerkioskpresence(
# jid, id, os, hostname, uuid_inventorymachine, agenttype, classutil, fromplugin=False
# ):
# """
# This function launch the kiosk actions when a prensence machine is active
# """
# logger.debug("kiosk handled")
## print jid, id, os, hostname, uuid_inventorymachine, agenttype, classutil
## get the profiles from the table machine.
# machine = XmppMasterDatabase().getMachinefromjid(jid)
# structuredatakiosk = get_packages_for_machine(machine)
# datas = {
# "subaction": "initialisation_kiosk",
# "data": {"action": "packages", "packages_list": structuredatakiosk},
# }

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

# tree = get_ou_tree()

# OU = list(set(OUmachine + OUuser))

# for ou in OU:
# tmp = [ou]
# partial = tree.search(ou)
# partial.recursive_parent(tmp)

## search packages for the applied profiles
# list_profile_packages = KioskDatabase().get_profile_list_for_OUList(tmp)
# if list_profile_packages is None:
## TODO
## linux and mac os does not have an Organization Unit.
## For mac os and linux, profile association will be done on the login name.
# return

# granted_packages = []
# for element in list_profile_packages:
# granted_packages += KioskDatabase().get_acknowledges_for_package_profile(
# element[9], element[6], machine["lastuser"]
# )
# list_software_glpi = []
# softwareonmachine = Glpi().getLastMachineInventoryPart(
# machine["uuid_inventorymachine"],
# "Softwares",
# 0,
# -1,
# "",
# {"hide_win_updates": True, "history_delta": ""},
# )
# for x in softwareonmachine:
# list_software_glpi.append([x[0][1], x[1][1], x[2][1]])

# structuredatakiosk = []

## Create structuredatakiosk for initialization
# for packageprofile in list_profile_packages:
# structuredatakiosk.append(
# __search_software_in_glpi(
# list_software_glpi, granted_packages, packageprofile, structuredatakiosk
# )
# )
# logger.debug(
# "initialisation kiosk %s on machine %s"
# % (structuredatakiosk, machine["hostname"])
# )

# return structuredatakiosk


# def get_ou_tree():
# """This function returns the list of OUs

# Returns:
# TreeOU object which contains all the OUs.
# or
# returns False for some issues
# """

## Check the ldap config
# config = PluginConfigFactory.new(BasePluginConfig, "base")
# kconfig = KioskConfig("kiosk")

# ous = []

# if kconfig.use_external_ldap is False:
# ous = XmppMasterDatabase().get_ou_list_from_machines()
# elif config.has_section("authentication_externalldap"):
# id = str(uuid.uuid4())
# file = "/tmp/ous-" + id

## Get the parameters from the config file
# ldapurl = config.get("authentication_externalldap", "ldapurl")
# suffix = config.get("authentication_externalldap", "suffix_ou")
# bindname = config.get("authentication_externalldap", "bindname")
# bindpasswd = config.get("authentication_externalldap", "bindpasswd")

## Execute the command which get the OU list and write into the specified file
# command = """ldapsearch -o ldif-wrap=no -H %s -x -b "%s" -D "%s" -w %s -LLL "(
# objectClass=organizationalUnit)" dn > %s""" % (
# ldapurl,
# suffix,
# bindname,
# bindpasswd,
# file,
# )

# os.system(command)

## Parse the file
# with open(file, "r") as ou_file:
# lines = ou_file.read().splitlines()
## The lines that don't start by 'dn' are ignored
# lines = [element for element in lines if element.startswith("dn")]

## Parse the result for each lines
# for element in lines:
## Lines starts with dn:: are get in base64 format
# if element.startswith("dn:: "):
# tmp = element.split("::")
# ou = base64.b64decode(tmp[1])

# else:
# tmp = element.split(": ")
# ou = tmp[1]
## Format the result
# ou = ou.replace(",OU=", " < ")
# ou = ou.replace("OU=", "")
# ou = re.sub(",DC=(.+)", "", ou)

# ou = ou.split(" < ")
# ou.reverse()
# ou = "/".join(ou)
## Save the content into a list
# ous.append(ou)

## Delete the file
# os.remove(file)
# else:
# return False

# tree = TreeOU()
# for line in ous:
# tree.create_recursively(line)

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


# def parsexmppjsonfile(path):
# datastr = file_get_contents(path)

# datastr = re.sub(r"(?i) *: *false", " : false", datastr)
# datastr = re.sub(r"(?i) *: *true", " : true", datastr)

# file_put_contents(path, datastr)


# def initialisekiosk(data, message, xmppobject):
# machine = XmppMasterDatabase().getMachinefromjid(message['from'])
# if "userlist" and "oumachine" and "ouuser" in data:
# if len(data['userlist']) == 0:
# user = ""
# else:
# user = data['userlist'][0]
# print "call updatemachineAD"
# XmppMasterDatabase().updatemachineAD(machine['id'], user, data['oumachine'], data['ouuser'])


# initializationdatakiosk = handlerkioskpresence( message['from'],
# machine['id'],
# machine['platform'],
# machine['hostname'],
# machine['uuid_inventorymachine'],
# machine['agenttype'],
# classutil = machine['classutil'],
# fromplugin = True)

# datasend = {
# "sessionid" : name_random(6, "initialisation_kiosk"),
# "action" : "kiosk",
# "data" : initializationdatakiosk
# }
# xmppobject.send_message(mto= message['from'],
# mbody=json.dumps(datasend),
# mtype='chat')


# def deploypackage(data, message, xmppobject, sessionid):
# machine =  XmppMasterDatabase().getMachinefromjid( message['from'])

## Get the actual timestamp in utc format
# current_date = datetime.datetime.utcnow()
# current_date = current_date.replace(tzinfo=pytz.UTC)
# section = ""

# if "utcdatetime" in data:
# date_str = data["utcdatetime"].replace("(","")
# date_str = date_str.replace(")","")
# date_list_tmp = date_str.split(",")
# date_list = []
# for element in date_list_tmp:
# date_list.append(int(element))

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

# idtarget = target['id']

# MscDatabase().xmpp_create_CommandsOnHost(commandid,
# idtarget,
# machine['hostname'],
# commandstop,
# commandstart)

## Write advanced parameter for the deployment
# XmppMasterDatabase().addlogincommand(
# nameuser,
# commandid,
# "",
# "",
# "",
# "",
# section,
# 0,
# 0,
# 0,
# 0,
# {})

# sessionid = name_random(5, "deploykiosk_")
# name = managepackage.getnamepackagefromuuidpackage(data['uuid'])

# path = managepackage.getpathpackagename(name)

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
# timestamp_install_date = int(time.mktime(install_date.timetuple()))
# xmppobject.xmpplog("Start deploy on machine %s"%jidmachine,
# type='deploy',
# sessionname=sessionid,
# priority=-1,
# action="",
# who=nameuser,
# how="",
# why=xmppobject.boundjid.bare,
# module="Deployment | Start | Creation",
# date=timestamp_install_date,
# fromuser=nameuser,
# touser="")