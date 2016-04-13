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
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,os,platform

fileconf="agentconf.ini"

if sys.platform.startswith('linux'):
    fileconf="agentconf.ini"
elif sys.platform.startswith('win'):
    fileconf="agentconf.ini"
elif sys.platform.startswith('darwin'):
    fileconf="agentconf.ini"
    
   
