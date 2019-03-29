#!/usr/bin/env python
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
# Attention, ce programme doit ce trouver dans le même répertoire que l'agent
# file : le replicator

# fait une copy  de l'agent actuel.
import os
import sys
import logging
import json
import zlib
import base64
import traceback
import random
import hashlib
import unittest
import replicator
if sys.platform.startswith('win'):
    import _winreg


class testreplicator(unittest.TestCase):
        def setUp(self):
            """Initialisation des tests."""
            self.list1= {
                "connectionagent.py": "0f43ee1244873aa3309628c2660ec7f3", 
                "agentxmpp.py": "3b00c082eaff89ab6b270fb86dadc1c2", 
                "launcher.py": "eb46d376f37db6608a4f70c5a0a9475a"}
            self.list2= {
                "connectionagent.py": "0f43ee1244873aa3309628c2660ec7f3", 
                "agentxmpp.py": "3b00c082eaff89ab6b270fb86dadc1c2", 
                "launcher.py": "eb46d376f37db6608a4f70c5a0a9475a",
                "manage_process.py": "f49e227c8cd28bef2845c26db6ead66b"}
            self.list3= {
                "connectionagent.py": "0f43ee1244873aa3309628c2660ec7f2", 
                "agentxmpp.py": "3b00c082eaff89ab6b270fb86dadc1c2",
                "utils_psutil.py": "501effae5f5f5c2170ca4a2d806dc2da", 
                "manage_event.py": "f51edca85db6e07ad6dd011da048d2b9" }

        def test_search_file_to_copier_on_fichier_supplementaire(self):
            print "test function search_action_on_agent_cp_and_del(imagelist, machlist)"
            #test list de copy
            diff, supp = replicator.search_action_on_agent_cp_and_del( self.list2,
                                                                      self.list1)
            self.assertEqual(supp, [])
            self.assertEqual(diff, ["manage_process.py"])

            #test list fichier supprimer dans list machine
            diff, supp = replicator.search_action_on_agent_cp_and_del( self.list1,
                                                                      self.list2)
            self.assertEqual(supp,  ["manage_process.py"])
            self.assertEqual(diff,  [])

            # test rien a faire
            diff, supp = replicator.search_action_on_agent_cp_and_del( self.list1,
                                                                      self.list1)
            self.assertEqual(diff,  [])
            self.assertEqual(supp,  [])
            #test ajout et supp file in mach list
            diff, supp = replicator.search_action_on_agent_cp_and_del( self.list3,
                                                                      self.list1)
            self.assertEqual(diff.sort(),  ["connectionagent.py", "utils_psutil.py", "manage_event.py"].sort())
            self.assertEqual(supp,  ["launcher.py"])



unittest.main()
