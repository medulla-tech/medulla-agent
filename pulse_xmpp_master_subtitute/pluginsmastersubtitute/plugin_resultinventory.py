# -*- coding: utf-8 -*-
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

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "resultinventory", "TYPE": "subtitute"}

def getComputerByMac( mac):
    ret = Glpi().getMachineByMacAddress('imaging_module', mac)
    if type(ret) == list:
        if len(ret) != 0:
            return ret[0]
        else:
            return None
    return ret

#todo augmenter colonne type dans la table log.
def XmppUpdateInventoried(jid, machine):
    try:
        result = XmppMasterDatabase().listMacAdressforMachine(machine['id'])
        results = result[0].split(",")
        logging.getLogger().debug("listMacAdressforMachine   %s" % results)
        uuid = ''
        for t in results:
            logger.debug("TRAITEMENT POUR MAC ADRESS")
            computer = getComputerByMac(t)
            if computer != None:
                uuid = 'UUID' + str(computer.id)
                logger.debug("** Update uuid %s for machine %s " % (uuid, machine['jid']))
                if machine['uuid_inventorymachine'] != "":
                    logger.debug("** Update in Organization_ad uuid %s to %s " % (machine['uuid_inventorymachine'],
                                                                                    uuid))
                    XmppMasterDatabase().replace_Organization_ad_id_inventory(machine['uuid_inventorymachine'],
                                                                                uuid)
                XmppMasterDatabase().updateMachineidinventory(uuid, machine['id'])
                return True
    except Exception:
        logger.error("** Update error on inventory %s\n%s" % (jid, traceback.format_exc()))
    return False

def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    HEADER = {"Pragma": "no-cache",
              "User-Agent": "Proxy:FusionInventory/Pulse2/GLPI",
              "Content-Type": "application/x-compress",
              }
    try:
        logging.getLogger().debug("=====================================================")
        logging.getLogger().debug(plugin)
        logging.getLogger().debug("=====================================================")
        try:
            url = xmppobject.config.inventory_url
        except:
            url = "http://localhost:9999/"
        inventory = zlib.decompress(base64.b64decode(data['inventory']))
        request = urllib2.Request(url, inventory, HEADER)
        response = urllib2.urlopen(request)
        machine = XmppMasterDatabase().getMachinefromjid(msg['from'])
        nbsize = len(inventory)
        XmppMasterDatabase().setlogxmpp("inject inventory to Glpi",
                                        "Master",
                                        "",
                                        0,
                                        msg['from'],
                                        'Manuel',
                                        '',
                                        'QuickAction |Inventory | Inventory requested',
                                        '',
                                        '',
                                        "Master")
        if nbsize < 250:
            XmppMasterDatabase().setlogxmpp('<font color="Orange">Warning, Inventory XML size %s byte</font>' % nbsize,
                                            "Master",
                                            "",
                                            0,
                                            msg['from'],
                                            'Manuel',
                                            '',
                                            'Inventory | Notify',
                                            '',
                                            '',
                                            "Master")
        time.sleep(15)
        if not XmppUpdateInventoried(msg['from'], machine):
            XmppMasterDatabase().setlogxmpp('<font color="deeppink">Error Injection Inventory for Machine %s</font>' % (msg['from']),
                                            "Master",
                                            "",
                                            0,
                                            msg['from'],
                                            'auto',
                                            '',
                                            'Inventory | Notify | Error',
                                            '',
                                            '',
                                            "InvServer")

        # save registry inventory
        try:
            reginventory = json.loads(base64.b64decode(data['reginventory']))
        except:
            reginventory = False
        # send inventory to inventory server
        
        XmppMasterDatabase().setlogxmpp("inject inventory to Glpi",
                                        "Master",
                                        "",
                                        0,
                                        msg['from'],
                                        'Manuel',
                                        '',
                                        'QuickAction |Inventory | Inventory requested',
                                        '',
                                        '',
                                        "Master")

        if reginventory:
            counter = 0
            while True:
                time.sleep(counter)
                if machine['id'] or counter >= 10:
                    break
            logging.getLogger().debug("Computers ID: %s" % machine['id'])
            nb_iter = int(reginventory['info']['max_key_index']) + 1
            for num in range(1, nb_iter):
                reg_key_num = 'reg_key_'+str(num)
                try:
                    reg_key = reginventory[reg_key_num]['key'].strip('"')
                    reg_key_value = reginventory[reg_key_num]['value'].strip('"')
                    key_name = reg_key.split('\\')[-1]
                    logging.getLogger().debug("Registry information:")
                    logging.getLogger().debug("  reg_key_num: %s" % reg_key_num)
                    logging.getLogger().debug("  reg_key: %s" % reg_key)
                    logging.getLogger().debug("  reg_key_value: %s" % reg_key_value)
                    logging.getLogger().debug("  key_name: %s" % key_name)
                    registry_id = Glpi().getRegistryCollect(reg_key)
                    logging.getLogger().debug("  registry_id: %s" % registry_id)
                    XmppMasterDatabase().setlogxmpp("Inventory Registry information: [machine :  %s][reg_key_num : %s]"
                                                    "[reg_key: %s][reg_key_value : %s]"
                                                    "[key_name : %s]" % (
                                                        msg['from'], reg_key_num, reg_key, reg_key_value, key_name),
                                                    "Master",
                                                    "",
                                                    0,
                                                    msg['from'],
                                                    'Manuel',
                                                    '',
                                                    'QuickAction |Inventory | Inventory requested',
                                                    '',
                                                    '',
                                                    "Master")
                    Glpi().addRegistryCollectContent(machine['id'], registry_id, key_name, reg_key_value)
                except Exception, e:
                    logger.error("getting key: %s\n%s" %(str(e),traceback.format_exc()))
                    pass
        time.sleep(25)
        # restart agent
        # xmppobject.restartAgent(msg['from'])
    except Exception, e:
        logger.error("%s\n%s"%(str(e), traceback.format_exc()))
