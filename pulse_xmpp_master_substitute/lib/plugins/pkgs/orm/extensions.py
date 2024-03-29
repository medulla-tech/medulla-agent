# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007-2010 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


""" Class to map pkgs.Extensions to SA
"""


class Extensions(object):
    """Mapping between pkgs.extensions and SA"""

    def getId(self):
        if self.id is not None:
            return self.id
        else:
            return 0

    def getRule_order(self):
        if self.rule_order is not None:
            return self.rule_order
        else:
            return 0

    def getRule_name(self):
        if self.rule_name is not None:
            return self.rule_name
        else:
            return ""

    def getName(self):
        if self.name is not None:
            return self.name
        else:
            return ""

    def getExtension(self):
        if self.extension is not None:
            return self.extension
        else:
            return ""

    def getMagic_command(self):
        if self.magic_command is not None:
            return self.magic_command
        else:
            return ""

    def getBang(self):
        if self.bang is not None:
            return self.bang
        else:
            return ""

    def getFile(self):
        if self.file is not None:
            return self.file
        else:
            return ""

    def getStrings(self):
        if self.strings is not None:
            return self.strings
        else:
            return ""

    def getProposition(self):
        if self.proposition is not None:
            return self.proposition
        else:
            return ""

    def getDescription(self):
        if self.description is not None:
            return self.description
        else:
            return ""

    def to_array(self):
        return {
            "id": self.getId(),
            "rule_order": self.getRule_order(),
            "rule_name": self.getRule_name(),
            "name": self.getName(),
            "extension": self.getExtension(),
            "magic_command": self.getMagic_command(),
            "bang": self.getBang(),
            "file": self.getFile(),
            "strings": self.getStrings(),
            "proposition": self.getProposition(),
            "description": self.getDescription(),
        }

    def toH(self):
        return {
            "id": self.id,
            "rule_order": self.rule_order,
            "rule_name": self.rule_name,
            "name": self.name,
            "extension": self.extension,
            "magic_command": self.magic_command,
            "bang": self.bang,
            "file": self.file,
            "strings": self.strings,
            "proposition": self.proposition,
            "description": self.description,
        }
