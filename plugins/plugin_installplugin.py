/**
 * (c) 2016 Siveo, http://http://www.siveo.net
 *
 * $Id$
 *
 * This file is part of Pulse .
 *
 * Pulse is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Pulse is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Pulse.  If not, see <http://www.gnu.org/licenses/>.
 */
 
# -*- coding: utf-8 -*-
import sys, os



plugin={"VERSION": "1.0", "NAME" :"installplugin"}

def action( objetxmpp, action, sessionid, data, message, dataerreur ):
    if action == 'installplugin':
        if len(data) != 0 :
            pl = sys.platform
            if pl.startswith('win'):
                data = data.replace("\n","\r\n");
            elif pl.startswith('linux'):
                pass
            else:
                pass
            namefile =  os.path.join('plugins',data['pluginname'])
            try:
                fileplugin = open(namefile, "w")
                fileplugin.write(str(data['datafile']))
                fileplugin.close()
            except :
                print "Error: cannor write on file"
                return
            msg = "install plugin %s on %s"%(data['pluginname'],message['to'].user)
            objetxmpp.loginformation(msg)
