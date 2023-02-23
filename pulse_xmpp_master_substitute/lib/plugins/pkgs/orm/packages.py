# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007-2009 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

""" Class to map msc.commands_on_host to SA
"""

import logging
import time
import datetime
import sqlalchemy.orm


class Packages(object):
    """ Mapping between msc.commands_on_host and SA
    """

    def getId(self):
        if self.id is not None:
            return self.id
        else:
            return 0

    def getLabel(self):
        if self.label != None:
            return self.label
        else:
            return ""

    def getDescription(self):
        if self.description is not None:
            return self.description
        else:
            return ""

    def getUuid(self):
        if self.uuid is not None:
            return self.uuid
        else:
            return ""

    def getVersion(self):
        if self.version is not None:
            return self.version
        else:
            return ""

    def getOs(self):
        if self.os is not None:
            return self.os
        else:
            return ""

    def getMetaGenerator(self):
        if self.metagenerator is not None:
            return self.metagenerator
        else:
            return "expert"

    def getEntity_id(self):
        if self.entity_id is not None:
            return self.entity_id
        else:
            return "0"

    def getSub_packages(self):
        if self.sub_packages is not None:
            return self.sub_packages
        else:
            return ""

    def getReboot(self):
        if self.reboot is not None:
            return self.getReboot
        else:
            return ""

    def getInventory_associateinventory(self):
        if self.inventory_associateinventory is not None:
            return self.inventory_associateinventory
        else:
            return ""

    def getInventory_licenses(self):
        if self.inventory_licenses is not None:
            return self.inventory_licenses
        else:
            return ""

    def getQversion(self):
        if self.Qversion is not None:
            return self.Qversion
        else:
            return ""

    def getQvendor(self):
        if self.Qvendor is not None:
            return self.Qvendor
        else:
            return ""

    def getQsoftware(self):
        if self.Qsoftware is not None:
            return self.Qsoftware
        else:
            return ""

    def getBoolcnd(self):
        if self.boolcnd is not None:
            return self.boolcnd
        else:
            return 0

    def getPostCommandSuccess_command(self):
        if self.postCommandSuccess_command is not None:
            return self.postCommandSuccess_command
        else:
            return ""

    def getPostCommandSuccess_name(self):
        if self.postCommandSuccess_name is not None:
            return self.postCommandSuccess_name
        else:
            return ""
    def getInstallInit_command(self):
        if self.installInit_command is not None:
            return self.installInit_command
        else:
            return ""

    def getInstallInit_name(self):
        if self.installInit_name is not None:
            return self.installInit_name
        else:
            return ""

    def getPostCommandFailure_command(self):
        if self.postCommandFailure_command is not None:
            return self.postCommandFailure_command
        else:
            return ""

    def getPostCommandFailure_name(self):
        if self.postCommandFailure_name is not None:
            return self.postCommandFailure_name
        else:
            return ""

    def getCommand_command(self):
        if self.command_command is not None:
            return self.command_command
        else:
            return ""

    def getCommand_name(self):
        if self.command_name is not None:
            return self.command_name
        else:
            return ""

    def getPreCommand_command(self):
        if self.preCommand_command is not None:
            return self.preCommand_command
        else:
            return ""

    def getPreCommand_name(self):
        if self.preCommand_name is not None:
            return self.preCommand_name
        else:
            return ""

    def getpkgs_share_id(self):
        if self.pkgs_share_id is not None:
            return self.pkgs_share_id
        else:
            return None
        
    def getedition_status(self):
        if self.edition_status is not None:
            return self.edition_status
        else:
            return None

    def to_array(self):
        """
        This function serialize the object to dict.

        Returns:
            Dict of elements contained into the object.
        """
        return {
            'entity_id' : self.getEntity_id(),
            'description' : self.getDescription(),
            'sub_packages' : self.getSub_packages(),
            'id': self.getUuid(),
            'pk_id': self.getId(),
            'commands':{
                'postCommandSuccess': {
                    'command': self.getPostCommandSuccess_command(),
                    'name': self.getPostCommandSuccess_name()
                },
                'installInit':{
                    'command': self.getInstallInit_command(),
                    'name': self.getInstallInit_name()
                },
                "postCommandFailure": {
                    "command": self.getPostCommandFailure_command(),
                    "name": self.getPostCommandFailure_name(),
                },
                "command": {
                    "command": self.getCommand_command(),
                    "name": self.getCommand_name(),
                },
                "preCommand": {
                    "command": self.getPreCommand_command(),
                    "name": self.getPreCommand_name()
                }
            },
            'name': self.getLabel(),
            'targetos': self.getOs(),
            'reboot': self.getReboot(),
            'version': self.getVersion(),
            'inventory': {
                'associateinventory': self.getInventory_associateinventory(),
                'licenses': self.getInventory_licenses(),
                "queries": {
                    "Qversion": self.getQversion(),
                    "Qvendor": self.getQvendor(),
                    "boolcnd": self.getBoolcnd(),
                    "Qsoftware": self.getQsoftware()
                },
                "metagenerator": self.getMetaGenerator()
            }
        }


    def toH(self):
        return {'id': self.id,
                "label": self.label,
                "description": self.description,
                "uuid": self.uuid,
                "version": self.version,
                "os": self.os,
                "metagenerator": self.metagenerator,
                "entity_id": self.entity_id,
                "sub_packages": self.sub_packages,
                "reboot": self.reboot,
                "inventory_associateinventory": self.inventory_associateinventory,
                "inventory_licenses": self.inventory_licenses,
                "Qversion": self.Qversion,
                "Qvendor": self.Qvendor,
                "Qsoftware": self.Qsoftware,
                "boolcnd": self.boolcnd,
                "postCommandSuccess_command": self.postCommandSuccess_command,
                "postCommandSuccess_name": self.postCommandSuccess_name,
                "installInit_command": self.installInit_command,
                "installInit_name": self.installInit_name,
                "postCommandFailure_command": self.postCommandFailure_command,
                "postCommandFailure_name": self.postCommandFailure_name,
                "command_command": self.command_command,
                "command_name": self.command_name,
                "preCommand_command": self.preCommand_command,
                "preCommand_name": self.preCommand_name}
