# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import os
import logging
from .utils import file_get_contents, file_get_binarycontents
import json


class Update_Remote_Agent:
    """
    this class make finderspring of agent.
    Param : dir_agent_base is location of agent
    Param : autoupdate is switch for enable or disable remote update.
    """

    def __init__(self, dir_agent_base, autoupdate=True):
        self.dir_agent_base = dir_agent_base
        self.autoupdate = autoupdate
        self.directory = {
            "program_agent": {},
            "version": "",
            "version_agent": "",
            "lib_agent": {},
            "script_agent": {},
            "fingerprint": "",
        }
        # verify exist dir and create si not exit. The default mode is 0o777
        # (octal)
        dir_create = [
            dir_agent_base,
            os.path.join(dir_agent_base, "lib"),
            os.path.join(dir_agent_base, "script"),
        ]
        for path_dir_remoteagent in dir_create:
            if not os.path.exists(path_dir_remoteagent):
                os.makedirs(path_dir_remoteagent)
                logging.getLogger().debug(
                    "Creating folder for remote base agent : %s" % dir_agent_base
                )
        if os.path.exists(os.path.join(dir_agent_base, "agentversion")):
            self.load_list_md5_agentbase()

    def get_md5_descriptor_agent(self):
        return self.directory

    def md5_descriptor_agent_to_string(self):
        return json.dumps(self.get_md5_descriptor_agent(), indent=4)

    def get_fingerprint_agent_base(self):
        return self.directory["fingerprint"]

    def load_list_md5_agentbase(self):
        listmd5 = []
        self.directory = {
            "program_agent": {},
            "version": "",
            "version_agent": "",
            "lib_agent": {},
            "script_agent": {},
            "fingerprint": "",
        }
        self.directory["version"] = (
            file_get_contents(os.path.join(self.dir_agent_base, "agentversion"))
            .replace("\n", "")
            .replace("\r", "")
            .strip()
        )
        self.directory["version_agent"] = hashlib.md5(
            (self.directory["version"]).encode("utf-8")
        ).hexdigest()
        listmd5.append(self.directory["version_agent"])
        list_script_python_for_update = [
            "agentxmpp.py",
            "launcher.py",
            "connectionagent.py",
            "replicator.py",
        ]
        for filename in list_script_python_for_update:
            self.directory["program_agent"][filename] = hashlib.md5(
                file_get_binarycontents(os.path.join(self.dir_agent_base, filename))).hexdigest()
            listmd5.append(self.directory["program_agent"][filename])
        for filename in [
            x
            for x in os.listdir(os.path.join(self.dir_agent_base, "lib"))
            if x[-3:] == ".py"
        ]:
            self.directory["lib_agent"][filename] = hashlib.md5(
                file_get_binarycontents(os.path.join(self.dir_agent_base, "lib", filename))).hexdigest()
            listmd5.append(self.directory["lib_agent"][filename])
        for filename in [
            x
            for x in os.listdir(os.path.join(self.dir_agent_base, "script"))
            if x[-4:] == ".ps1"
        ]:
            self.directory["script_agent"][filename] = hashlib.md5(
                file_get_binarycontents(
                    os.path.join(self.dir_agent_base, "script", filename)).hexdigest()
            listmd5.append(self.directory["script_agent"][filename])
        listmd5.sort()
        self.directory["fingerprint"] = hashlib.md5(
            json.dumps(listmd5).encode("utf-8")
        ).hexdigest()
