# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007-2009 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


""" Class to map pkgs.syncthingsync to SA
"""


class Syncthingsync(object):
    """
    Mapping between pkgs.syncthingsync and SA
    """

    def getId(self):
        if self.id is not None:
            return self.id
        else:
            return 0

    def getDate(self):
        if self.date is not None:
            return self.date
        else:
            return ""

    def getUuidpackage(self):
        if self.uuidpackage is not None:
            return self.uuidpackage
        else:
            return ""

    def getTypesynchro(self):
        if self.typesynchro is not None:
            return self.typesynchro
        else:
            return ""

    def getRelayserver_jid(self):
        if self.relayserver_jid is not None:
            return self.relayserver_jid
        else:
            return ""

    def getWatching(self):
        if self.watching is not None:
            return self.watching
        else:
            return ""

    def to_array(self):
        """
        This function serialize the object to dict.

        Returns:
            Dict of elements contained into the object.
        """
        return {
            "id": self.getId(),
            "date": self.getDate(),
            "uuidpackage": self.getUuidpackage(),
            "typesynchro": self.getTypesynchro(),
            "relayserver_jid": self.getRelayserver_jid(),
            "watching": self.getWatching(),
        }
