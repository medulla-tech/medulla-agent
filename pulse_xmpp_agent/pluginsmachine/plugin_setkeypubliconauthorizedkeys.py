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




try:
    from  lib.utils import pluginprocess, install_or_uninstall_keypub_authorized_keys
except ImportError:
    from  lib.utils import pluginprocess, install_or_undinstall_keypub_authorized_keys as install_or_uninstall_keypub_authorized_keys


import logging

DEBUGPULSEPLUGIN = 25
plugin = { "VERSION" : "1.2", "NAME" : "setkeypubliconauthorizedkeys", "TYPE" : "machine" }
"""
    this plugin install la key from ARS sur AM for the packages transfert in mode push
"""

@pluginprocess
def action(xmppobject, action, sessionid, data, message, dataerreur, result):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s from %s"%(plugin,message['from']))
    logging.getLogger().debug("###################################################")
    resultkeyinstall = True
    resultkeyuninstall = True
    if 'actionasker' in data and data['actionasker'] != "":
        result['action'] = data['actionasker']

    if 'install' in data and data['install']:
        print "install"
        #install keypub in authorized_keys
        logging.getLogger().debug("install keypub in authorized_keys")
        resultkeyinstall = install_or_uninstall_keypub_authorized_keys(install = True, keypub = data['keypub'])
        result['data'] = {}
        result['data']['keyinstall'] = True
    else :
        #uninstall keppub in authorized_keys
        logging.getLogger().debug("uninstall keppub in authorized_keys")
        resultkeyuninstall = install_or_uninstall_keypub_authorized_keys(install = False,  keypub = data['keypub'])

    if not resultkeyinstall:
       logging.getLogger().debug("###################################################")
       logging.getLogger().debug("ERREUR PLUGIN setkeypubliconauthorizedkeys addition key pub")
       raise
    if not resultkeyuninstall:
       logging.getLogger().debug("###################################################")
       logging.getLogger().debug("ERREUR PLUGIN setkeypubliconauthorizedkeys remove key pub")
       raise
