# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net> 
# SPDX-License-Identifier: GPL-2.0-or-later 

import base64
import traceback
import os
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.manageRSAsigned import MsgsignedRSA
#from slixmpp import jid
from sleekxmpp import jid
from lib.utils import getRandomName
import re
from distutils.version import LooseVersion
import configparser
import netaddr

# this import will be used later
# import types

logger = logging.getLogger()

plugin = {"VERSION": "2.0", "NAME": "update_windows", "TYPE": "substitute"}

# function comment for next feature
# this functions will be used later
# def function_dynamique_declaration_plugin(xmppobject):
# xmppobject.changestatusin_plugin = types.MethodType(changestatusin_plugin, xmppobject)

# def changestatusin_plugin(self, msg_changed_status):
# logger.debug("chang status for %s"%msg_changed_status['from'])
# pass

def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    try:
        logger.debug("=====================================================")
        logger.debug(f'call {plugin} from {msg["from"]}')
        logger.debug("=====================================================")

        compteurcallplugin = getattr(xmppobject, f"num_call{action}")
        if compteurcallplugin == 0:
            try:
                xmppobject.registeryagent_showinfomachine
            except:
                xmppobject.registeryagent_showinfomachine=[]
            read_conf_remote_update_windows(xmppobject)
            logger.debug(
                f"Including debug information for list jid {xmppobject.registeryagent_showinfomachine}"
            )

            xmppobject.list_produits = []
            xmppobject.list_produits = XmppMasterDatabase().list_produits()

                    # return
                    # function comment for next feature
                    # this functions will be used later
                    # add function for event change staus des autre agent
                    # function_dynamique_declaration_plugin(xmppobject)
                    # intercepte event change status call function
        showinfobool = True
        traitement_update(xmppobject, action, sessionid, data, msg, ret)
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))



def exclude_update_in_select( msg, exclude_update, list_update ):
    res=[]
    for upd in list_update:
        if upd['kb'] in exclude_update['kb'] or upd['updateid'] in exclude_update['update_id']:
            # exclution suivant les regles definie
            #logger.debug("Excluding %s, %s, %s, %s" % (msg['from'], upd['kb'], upd['updateid'], upd['title']))
            continue
        logger.debug(
            f"Adding update {msg['from']}, {upd['kb']}, {upd['updateid']}, {upd['title']}"
        )
        res.append({ 'kb' : upd['kb'], 'updateid' : upd['updateid'], "title" : upd['title'], "tableproduct" : upd['tableproduct']})
    return res

def traitement_update(xmppobject, action, sessionid, data, msg, ret):
    logger.debug(f"PROCESSING UPDATES FOR {msg['from']} ")
    logger.debug(json.dumps(data, indent=4))
    logger.debug(
        f"Enabled products (xmppobject.list_produits):  {xmppobject.list_produits}"
    )
    # suivant type de windows exclude list produit

    list_table_product_select = list_produis_on(xmppobject, data, xmppobject.list_produits)
    logger.debug(
        f"For machine {msg['from']} only the following tables will be updated:  {list_table_product_select}"
    )
    machine = XmppMasterDatabase().getId_UuidFromJid( msg['from'])
    if not machine:
        logger.warning(f"Machine {msg['from']} is not yet registered")
        return
    #logger.info("filtersql %s" % filtersql)


    if not xmppobject.exclude_history_list:
        logger.debug("Checking against KB history list")
        kblistexclde = []
        if history_list_kb := XmppMasterDatabase().history_list_kb(
            data['system_info']['history_package_uuid']
        ):
            kblistexclde.extend(history_list_kb)
        kb_installed = [ x['HotFixID'].replace("KB","") for x in data['system_info']['kb_installed']]
        kblistexclde.extend(kb_installed)
        lkbe = f'"{",".join(kblistexclde)}"'
        data['system_info']["kb_list"]=lkbe
    logger.debug(f"""Installed KB list: {data['system_info']["kb_list"]}""")
    list_update=exclude_update=res_update=[]
    exclude_update = XmppMasterDatabase().test_black_list(msg['from'])
    for _ in range(10):
        logger.debug(f"Excluding updates for {msg['from']}: {exclude_update}")
    for t in list_table_product_select:
        if t == "up_packages_Win_Malicious_X64":
            # le traitement de cette mise a jour est dependante de la version revoyer par la machine du logiciel.
            # le kb n'est pas modifier.
            continue
        list_update=[]
        logger.debug(
            f"""Looking for product {t['name_procedure']} ({data['system_info']["kb_list"]})"""
        )

        list_update=XmppMasterDatabase().search_update_by_products(
                           tableproduct=t,
                           str_kb_list=data['system_info']["kb_list"])
        logger.debug("list_update search is : " % list_update)
        res_update.extend(exclude_update_in_select( msg, exclude_update, list_update ))
    #res_update.extend(exclude_update_in_select( msg, exclude_update, list_update ))

    if "up_packages_Win_Malicious_X64" in list_table_product_select:
        if 'malicious_software_removal_tool' in data['system_info'] and \
            "FileMajorPart" in data['system_info']['malicious_software_removal_tool'] and \
            "FileMinorPart" in data['system_info']['malicious_software_removal_tool'] and \
            data['system_info']['malicious_software_removal_tool']['FileMajorPart'] != "" and \
            data['system_info']['malicious_software_removal_tool']['FileMinorPart'] !="":
            list_update=[]
            # search malicious_software_removal_tool
            list_update = XmppMasterDatabase().search_update_windows_malicious_software_tool(
                data['system_info']['platform_info']['type'],data['system_info']['platform_info']['machine'],
                data['system_info']['malicious_software_removal_tool']['FileMajorPart'],
                data['system_info']['malicious_software_removal_tool']['FileMinorPart'])
            #logger.info("result search_update_windows_malicious_software_tool\n %s" % res)
            res_update.extend(exclude_update_in_select( msg, exclude_update, list_update))

    # update les updates windows a installer
    XmppMasterDatabase().del_all_Up_machine_windows(machine['id'])
    for t in res_update:
        logger.info(f"Enabling update {t['updateid']}: {t['title']} - {t['kb']}")
        XmppMasterDatabase().setUp_machine_windows(machine['id'],
                                                    t['updateid'],
                                                    kb=t['kb'],
                                                    deployment_intervals=xmppobject.deployment_intervals)
        # on add ou update le kb dans la gray list
        XmppMasterDatabase().setUp_machine_windows_gray_list(t['updateid'], t['tableproduct'])

def list_produis_on(xmppobject, data, list_produits):
    listpack = []
    def del_element(x):
        if x in listpack:
            listpack.remove(x)

    for t in  list_produits:
        listpack.append(t['name_procedure'])
    logger.debug(f"listin fonction  selectionne package  {list_produits}  ")
    if data['system_info']['platform_info']['machine'] == "x64":
        if data['system_info']['platform_info']['type'] == "Windows 10":
            del_element("up_packages_Win11_X64")
            if data['system_info']['infobuild']['DisplayVersion'] =="21H2":
                del_element("up_packages_Win10_X64_1903")
                del_element("up_packages_Win10_X64_21H1")
                del_element("up_packages_Win10_X64_22H2")
            elif data['system_info']['infobuild']['DisplayVersion'] =="21H1":
                del_element("up_packages_Win10_X64_1903")
                del_element("up_packages_Win10_X64_21H2")
            else:
                del_element("up_packages_Win10_X64_21H1")
                del_element("up_packages_Win10_X64_21H2")
        else:
            del_element("up_packages_Win10_X64_21H1")
            del_element("up_packages_Win10_X64_21H2")
            del_element("up_packages_Win10_X64_1903")
    else:
        # on ne regarde pas les update x64
        liste_a_supprimer=["up_packages_Win10_X64_21H1", "up_packages_Win10_X64_21H2",
       "up_packages_Win10_X64_1903", "up_packages_Win11_X64", "up_packages_Win_Malicious_X64",
        "up_packages_office_2003_64bit", "up_packages_office_2007_64bit", "up_packages_office_2010_64bit",
       "up_packages_office_2013_64bit", "up_packages_office_2016_64bit" ]
        listpack = [element for element in listpack if element not in liste_a_supprimer]
    prds =  [ {'name_procedure' : element } for element in listpack if  element != "" ]
    return prds

def read_conf_remote_update_windows(xmppobject):
    xmppobject.exclude_history_list = True
    try:
        logger.debug("Initializing plugin :% s " % plugin["NAME"])
        namefichierconf = plugin["NAME"] + ".ini"
        pathfileconf = os.path.join(xmppobject.config.pathdirconffile, namefichierconf)

        if not os.path.isfile(pathfileconf):
            logger.error(
                "Plugin %s\nConfiguration file :"
                "\n\t%s missing"
                "\neg conf:\n[parameters]"
                "\exclude_history_list= True\n"% (plugin["NAME"], pathfileconf)
            )
            xmppobject.pluginlistregistered = []
            xmppobject.pluginlistunregistered = []
        else:
            Config = configparser.ConfigParser()
            Config.read(pathfileconf)
            logger.debug(f'Config file {pathfileconf} for plugin {plugin["NAME"]}')
            if os.path.exists(f"{pathfileconf}.local"):
                Config.read(f"{pathfileconf}.local")
                logger.debug(f"read file {pathfileconf}.local")

            if Config.has_option("parameters", "exclude_history_list"):
                xmppobject.exclude_history_list = Config.getboolean('parameters', 'exclude_history_list')
            else:
                xmppobject.exclude_history_list = true
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))

    xmppobject.deployment_intervals = ""
    if Config.has_option("parameters", "deployment_intervals"):
        xmppobject.deployment_intervals = Config.get('parameters', 'deployment_intervals')
