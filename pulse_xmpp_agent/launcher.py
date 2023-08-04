#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import logging
import platform
import traceback
import hashlib

from optparse import OptionParser
import os
import subprocess
import time
import json
import shutil
from datetime import datetime
import psutil

import signal
import configparser

if sys.platform.startswith("win"):
    import win32con
    import win32api

logger = logging.getLogger()

filePath = os.path.dirname(os.path.realpath(__file__))


def singletonclass(class_):
    instances = {}

    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]

    return getinstance


@singletonclass
class global_data_process:
    def __init__(self):
        self.PIDagent = 0
        self.ProcessObj = None
        self.cmd = ""
        self.pid_child = []
        self.terminate_process = False
        self.pid_children = []

    def load_child_process(self):
        """
        This function checks the pid of the medulla agent
        children processes

        This is a Linux and Darwin only function.
        """
        if self.ProcessObj is not None and self.PIDagent != 0:
            parent = psutil.Process(self.PIDagent)
            children = parent.children(recursive=True)
            listpid = [child.pid for child in children]
            self.pid_children.extend(listpid)
            self.pid_children = list(set(self.pid_children))
        list_defunct = [
            pid_child
            for pid_child in self.pid_children
            if not psutil.pid_exists(pid_child)
        ]
        for pid_defunct in list_defunct:
            try:
                self.pid_children.remove(pid_defunct)
            except ValueError:
                pass

    def list_child_exist(self):
        """
        This function is used to find if a
        child process exists.

        Returns:
            It returns True if the process exists.
                       False otherwise.
        """
        for pid_child in self.pid_children:
            return bool(psutil.pid_exists(pid_child))

    def is_alive(self):
        """
        This function is used to check if the child processs is still alive.
        Returns:
            It retuns True if the child process is alive
                      False if the child process is not alive
        """
        # when poll() is set to None, it means that the process is not done yet.
        if self.ProcessObj is not None:
            if self.ProcessObj.poll() is None:
                # The process is still running.
                return True
            self.stop_process_agent()
            self.ProcessObj.wait()
            self.PIDagent = 0
            self.ProcessObj = None
            self.pid_child = []
        return False

    def stop_process_agent(self, is_parent=True):
        """
        Stops the parent and child processes.
        """
        if self.ProcessObj is not None:
            if self.PIDagent != 0:
                parent = psutil.Process(self.PIDagent)
                children = parent.children(recursive=True)
                for child in children:
                    child.kill()
                gone, still_alive = psutil.wait_procs(children, timeout=5)
                if is_parent:
                    try:
                        logger.debug(f"kill parent process {parent.pid}")
                        parent.kill()
                        parent.wait(5)
                    except:
                        pass
                    self.PIDagent = 0
                    self.ProcessObj = None
                    self.pid_children = []
        self.display_Process()

    def start_process_agent(self, prog):
        prog=[ x.replace('"','') for x in prog ]
        if self.ProcessObj is None:
            self.cmd = prog
            if sys.platform.startswith("win"):
                self.ProcessObj = subprocess.Popen(
                    self.cmd, stdout=None, stderr=None, stdin=None, close_fds=True
                )
            else:
                self.ProcessObj = subprocess.Popen(
                    self.cmd,
                    stdout=None,
                    stderr=None,
                    stdin=None,
                    close_fds=True,
                    preexec_fn=os.setpgrp,
                )
            self.PIDagent = self.ProcessObj.pid
            time.sleep(1)
            self.load_child_process()
            self.display_Process()

    def display_Process(self):
        try:
            if self.ProcessObj is not None:
                strpid = f"PID agent {self.PIDagent}"
                logger.debug(strpid)
                logstring = "\\_ -Launcher\n    \\_ -%s" % self.PIDagent
                for childpid in self.pid_child:
                    logstring = logstring + "\n\t\\_ -%s" % childpid
                logger.debug("\n%s" % logstring)
            else:
                logger.debug("No processes started.")
        except:
            pass

    def _CtrlHandler(self, evt):
        """## todo intercep message in console program
        win32con.WM_QUERYENDSESSION win32con.WM_POWERBROADCAS(PBT_APMSUSPEND
        """
        if sys.platform.startswith("win"):
            if evt == win32con.CTRL_SHUTDOWN_EVENT:
                logger.debug("SIGNAL EVENT CTRL_SHUTDOWN_EVENT")
                self.terminate_process = True
                self.stop_process_agent()
                return True
            elif evt == win32con.CTRL_LOGOFF_EVENT:
                logger.debug("SIGNAL EVENT CTRL_LOGOFF EVENT")
                return True
            elif evt == win32con.CTRL_BREAK_EVENT:
                logger.debug("SIGNAL EVENT CTRL_BREAK_EVENT")
                return True
            elif evt == win32con.CTRL_CLOSE_EVENT:
                logger.debug("SIGNAL EVENT CTRL_CLOSE_EVENT")
                return True
            elif evt == win32con.CTRL_C_EVENT:
                logger.debug("SIGNAL EVENT CTRL_C_EVENT")
                self.terminate_process = True
                self.stop_process_agent()
                return True
            logger.debug("SIGNAL EVENT INCONUE")
        return False

    def signal_handler(self, signal_in, frame):
        if signal_in in [signal.SIGINT, signal.SIGQUIT, signal.SIGQUIT]:
            logger.debug(f"SIGNAL EVENT {signal_in}")
            self.terminate_process = True
            self.stop_process_agent()


class base_folder:
    def __init__(self):
        self.path_agent = os.path.join(os.path.dirname(os.path.realpath(__file__)))
        self.path_rescue = os.path.join(self.path_agent, "agentrescue")

        #'launcher.py',
        self.list_script_python_for_update = [
            "agentxmpp.py",
            "connectionagent.py",
            "replicator.py",
        ]

        self.folder_rescue_py = [
            "lib",
            "pluginsmachine",
            "pluginsrelay",
            "descriptor_scheduler_machine",
            "descriptor_scheduler_relay",
        ]

        self.clean_folder = [
            "cycle",
            os.path.join("lib", "INFOSTMP"),
            "sessionsmachine",
            "INFOSTMP",
        ]

    def _exist_rescue(self):
        """
        Tests if the rescue Agent exists
        Return:
            It returns True if it exists. False otherwise.
        """
        return bool(os.path.isdir(self.path_rescue))

    def _clean_rescue_agent(self):
        """
        It removes the rescue agent from the filesystem.
        """
        if self._exist_rescue():
            logger.debug(f"We are removing the rescue agent from {self.path_rescue}")
            shutil.rmtree(self.path_rescue)

    def copytree1(self, src, dst, symlinks=False, ignore=None):
        """
        See shutil.copytree documentation:
        https://docs.python.org/2/library/shutil.html#shutil.copytree
        """
        if not os.path.exists(dst):
            os.makedirs(dst)
        for item in os.listdir(src):
            s = os.path.join(src, item)
            d = os.path.join(dst, item)
            if os.path.isdir(s):
                self.copytree1(s, d, symlinks, ignore)
            elif not os.path.exists(d) or os.stat(s).st_mtime - os.stat(d).st_mtime > 1:
                shutil.copy2(s, d)

    def copytree(self, src, dst, symlinks=False, ignore=None):
        """
        See shutil.copytree documentation:
        https://docs.python.org/2/library/shutil.html#shutil.copytree
        """
        logger.debug(f"copytree {src} ")
        for item in os.listdir(src):
            s = os.path.join(src, item)
            d = os.path.join(dst, item)
            if os.path.isdir(s):
                shutil.copytree(s, d, symlinks, ignore)
            else:
                shutil.copy2(s, d)

    def remove_and_copy(self, src, dest):
        """
        This function is used to copy a folder to
        an other destination.
        Before doing the copy it removes the dest folder
        if it exists.
        Args:
            src: The source location of the folder
            dst: The destination where we copy.
        """
        if os.path.isfile(dest):
            logger.debug(f"remove {dest}")
            os.remove(dest)
        logger.debug(f"reinstall {src} {dest}")
        shutil.copy2(src, dest)

    def clean_agent_src(self):
        """
        It cleans/removes folders from the agent installation.
        The folders to be removed are:
                  - cycle
                  - lib\INFOSTMP
                  - sessionsmachine
                  - INFOSTMP
        If the folders does not exist, we create them.
        """
        for folder in self.clean_folder:
            src = os.path.join(self.path_agent, folder)
            if os.path.isdir(src):
                shutil.rmtree(src)
            if not os.path.isdir(src):
                os.makedirs(src)

    def _create_folder_rescue(self):
        """
        It creates the rescue folder structure.
        """
        if not os.path.isdir(self.path_rescue):
            os.makedirs(self.path_rescue)

        for folder in self.folder_rescue_py:
            if not os.path.isdir(os.path.join(self.path_rescue, folder)):
                os.makedirs(os.path.join(self.path_rescue, folder))

        rescue_structure = ["script", "etc", "fileviewer", "keys", "JIDSUFFIXE"]
        for folder in rescue_structure:
            if not os.path.isdir(os.path.join(self.path_rescue, folder)):
                os.makedirs(os.path.join(self.path_rescue, folder))


class info_create_rescue_agent(base_folder):
    """
    This class is used to create the rescue agent structure.
    """

    def __init__(self):
        """
        Initialise some variable used in the class.
        """
        base_folder.__init__(self)
        self._path_files_py_agent()
        self.folderlistscript = os.path.join(self.path_agent, "script")
        self.files_agent_script = [
            x
            for x in os.listdir(self.folderlistscript)
            if os.path.isfile(os.path.join(self.folderlistscript, x))
            and x[-4:] != ".pyc"
        ]

        self.path_files_configuration = directoryconffile()
        self.list_config_file_ini = [
            x
            for x in os.listdir(self.path_files_configuration)
            if os.path.isfile(os.path.join(self.path_files_configuration, x))
            and (x[-4:] == ".ini" or x[-10:] == ".ini.local")
        ]

    def _path_files_py_agent(self):
        """ """
        self.files_agent = {}
        for folder in self.folder_rescue_py:
            folder_list = os.path.join(self.path_agent, folder)
            if os.path.isdir(folder_list):
                self.files_agent[folder] = [
                    x for x in os.listdir(folder_list) if x[-3:] == ".py"
                ]
            else:
                self.files_agent[folder] = []


class info_rescue_reinstall(base_folder):
    def __init__(self):
        """
        Initialise some variable used in the class.
        """
        base_folder.__init__(self)
        self._path_files_py_agent()
        self.folderlistscript = os.path.join(self.path_rescue, "script")
        self.files_agent_script = [
            x
            for x in os.listdir(self.folderlistscript)
            if os.path.isfile(os.path.join(self.folderlistscript, x))
            and x[-4:] != ".pyc"
        ]

        self.path_files_configuration = os.path.join(self.path_rescue, "etc")
        self.list_config_file_ini = [
            x
            for x in os.listdir(self.path_files_configuration)
            if os.path.isfile(os.path.join(self.path_files_configuration, x))
            and (x[-4:] == ".ini" or x[-10:] == ".ini.local")
        ]

    def _path_files_py_agent(self):
        self.files_agent = {}
        for foldercreate in self.folder_rescue_py:
            folderlist = os.path.join(self.path_rescue, foldercreate)
            if os.path.isdir(folderlist):
                self.files_agent[foldercreate] = [
                    x for x in os.listdir(folderlist) if x[-3:] == ".py"
                ]
            else:
                self.files_agent[foldercreate] = []


class create_rescue_agent:
    """
    This class is used to create the rescue agent ( with files ).
    """

    def __init__(self):
        self.info = info_create_rescue_agent()

    def save_rescue_src(self, install=False):
        """
        This function is used to copy files from a working
        version of the agent on the rescue folder.
        """
        self.info._clean_rescue_agent()
        self.info._create_folder_rescue()
        logger.debug("We are copying the file agentversion")
        src = os.path.join(self.info.path_agent, "agentversion")
        dest = os.path.join(self.info.path_rescue, "agentversion")
        logger.debug(f"copy {src} into {dest}")
        shutil.copy2(src, dest)

        logger.debug("We are copying the file JIDSUFFIXE")
        src = os.path.join(self.info.path_agent, "lib", "INFOSTMP", "JIDSUFFIXE")
        dest = os.path.join(self.info.path_rescue, "JIDSUFFIXE", "JIDSUFFIXE")
        logger.debug(f"copy {src} into {dest}")
        shutil.copy2(src, dest)

        logger.debug("We are copying the python files")
        for keysfile in self.info.files_agent:
            for files in self.info.files_agent[keysfile]:
                src = os.path.join(self.info.path_agent, keysfile, files)
                dest = os.path.join(self.info.path_rescue, keysfile, files)
                logger.debug(f"copy {src} into {dest}")
                shutil.copy2(src, dest)

        logger.debug("We are copying the major python scripts")
        for files in self.info.list_script_python_for_update:
            src = os.path.join(self.info.path_agent, files)
            dest = os.path.join(self.info.path_rescue, files)
            logger.debug(f"copy {src} into {dest}")
            shutil.copy2(src, dest)

        logger.debug("We are copying the other python scripts")
        for files in self.info.files_agent_script:
            src = os.path.join(self.info.path_agent, "script", files)
            dest = os.path.join(self.info.path_rescue, "script", files)
            logger.debug(f"copy {src} into {dest}")
            shutil.copy2(src, dest)

        logger.debug("We are copying the configuration files")
        for files in self.info.list_config_file_ini:
            src = os.path.join(self.info.path_files_configuration, files)
            dest = os.path.join(self.info.path_rescue, "etc", files)
            logger.debug(f"copy {src} into {dest}")
            try:
                shutil.copy2(src, dest)
            except:
                if not install:
                    logger.error(f"rescue save error copy {src} {dest}")
        logger.debug("rescue fileviewer resource")
        src = os.path.join(self.info.path_agent, "lib", "ressources", "fileviewer")
        dest = os.path.join(self.info.path_rescue, "fileviewer")
        logger.debug(f"copy {src} into {dest}")
        self.info.copytree(src, dest)


class install_rescue_image:
    def __init__(self):
        self.info = info_rescue_reinstall()

    def reinstall_agent_rescue(self):
        """
        It reinstalls a working Medulla Agent based on the rescue copy.
        """
        self.info.clean_agent_src()
        logger.debug("We are reinstalling the file agentversion")
        dest = os.path.join(self.info.path_agent, "agentversion")
        src = os.path.join(self.info.path_rescue, "agentversion")
        logger.debug(f"reinstalling {src} into {dest}")
        self.info.remove_and_copy(src, dest)

        logger.debug("We are copying the file JIDSUFFIXE")
        dest = os.path.join(self.info.path_agent, "lib", "INFOSTMP", "JIDSUFFIXE")
        src = os.path.join(self.info.path_rescue, "JIDSUFFIXE", "JIDSUFFIXE")
        logger.debug(f"reinstalling {src} into {dest}")
        self.info.remove_and_copy(src, dest)

        logger.debug("We are reintalling the python files")
        for keysfile in self.info.files_agent:
            logger.debug(f"***************** {keysfile} ***************")
            for files in self.info.files_agent[keysfile]:
                dest = os.path.join(self.info.path_agent, keysfile, files)
                src = os.path.join(self.info.path_rescue, keysfile, files)
                logger.debug(f"reinstall {src} into {dest}")
                self.info.remove_and_copy(src, dest)

        logger.debug("We are reintalling the python files")
        for files in self.info.list_script_python_for_update:
            dest = os.path.join(self.info.path_agent, files)
            src = os.path.join(self.info.path_rescue, files)
            logger.debug(f"reinstall {src} {dest}")
            self.info.remove_and_copy(src, dest)

        logger.debug("We are reintalling the other python scripts")
        for files in self.info.files_agent_script:
            dest = os.path.join(self.info.path_agent, "script", files)
            src = os.path.join(self.info.path_rescue, "script", files)
            logger.debug(f"reinstall {src} {dest}")
            self.info.remove_and_copy(src, dest)

        logger.debug("We are reintalling the configuration files")
        for files in self.info.list_config_file_ini:
            dest = os.path.join(directoryconffile(), files)
            src = os.path.join(self.info.path_rescue, "etc", files)
            logger.debug(f"reinstall {src} {dest}")
            try:
                self.info.remove_and_copy(src, dest)
            except:
                pass
        logger.debug("We are reinstalling the fileviewer resources")
        dest = os.path.join(self.info.path_agent, "lib", "ressources", "fileviewer")
        src = os.path.join(self.info.path_rescue, "fileviewer")
        logger.debug(f"reinstall {src} {dest}")
        shutil.rmtree(dest)
        self.info.copytree1(src, dest)


class Update_Remote_Agent:
    """
    this class make fingerprint of agent.
    """

    def __init__(self, dir_agent_base, autoupdate=True):
        """
        Initialisation function.

        It create the directory JSon Structure

        Args:
           dir_agent_base is location of agent
           autoupdate is switch for enable or disable remote update
        """
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
        # verify exist dir and create si not exit. The default mode is 0777 (octal)
        dir_create = [
            dir_agent_base,
            os.path.join(dir_agent_base, "lib"),
            os.path.join(dir_agent_base, "script"),
        ]
        for path_dir_remoteagent in dir_create:
            if not os.path.exists(path_dir_remoteagent):
                os.makedirs(path_dir_remoteagent)
                logging.getLogger().debug(
                    f"Creating folder for remote base agent : {dir_agent_base}"
                )
        if os.path.exists(os.path.join(dir_agent_base, "agentversion")):
            self.load_list_md5_agentbase()

    def get_md5_descriptor_agent(self):
        """
        This function allow to have the 'directory' structure in json format.

        Returns:
            It returns the whole directory
            (program_agent, version, version_agent,
              lib_agent, script_agent and fingerprint)
        """
        return self.directory

    def md5_descriptor_agent_to_string(self):
        """
        This function allow to have the 'directory' structure in string format.

        Returns:
            It returns the whole directory
            ( program_agent, version, version_agent,
              lib_agent, script_agent and fingerprint )
        """

        return json.dumps(self.get_md5_descriptor_agent(), indent=4)

    def get_fingerprint_agent_base(self):
        """
        This function allow to have the fingerprint in json format.

        Returns:
            It returns the fingerprint
        """

        return self.directory["fingerprint"]

    def load_list_md5_agentbase(self):
        """
        This function calculate the md5sum of all the files ( excepted the plugins ).
        It calculates the fingerprints of the agent too.
        It is stoted in a structure with the values.
        """
        # fingerprint de l'agent et le md5 de cette list ordonne au format string json
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
            self.directory["version"]
        ).hexdigest()
        listmd5 = [self.directory["version_agent"]]
        list_script_python_for_update = [
            "agentxmpp.py",
            "launcher.py",
            "connectionagent.py",
            "replicator.py",
        ]

        for fichiername in list_script_python_for_update:
            self.directory["program_agent"][fichiername] = hashlib.md5(
                file_get_contents(os.path.join(self.dir_agent_base, fichiername))
            ).hexdigest()
            listmd5.append(self.directory["program_agent"][fichiername])

        for fichiername in [
            x
            for x in os.listdir(os.path.join(self.dir_agent_base, "lib"))
            if x[-3:] == ".py"
        ]:
            self.directory["lib_agent"][fichiername] = hashlib.md5(
                file_get_contents(os.path.join(self.dir_agent_base, "lib", fichiername))
            ).hexdigest()
            listmd5.append(self.directory["lib_agent"][fichiername])
        for fichiername in [
            x
            for x in os.listdir(os.path.join(self.dir_agent_base, "script"))
            if x[-4:] == ".ps1"
        ]:
            self.directory["script_agent"][fichiername] = hashlib.md5(
                file_get_contents(
                    os.path.join(self.dir_agent_base, "script", fichiername)
                )
            ).hexdigest()
            listmd5.append(self.directory["script_agent"][fichiername])
        listmd5.sort()
        self.directory["fingerprint"] = hashlib.md5(json.dumps(listmd5)).hexdigest()


def agentinfoversion(xmppobject):
    """
    return information on agent.

    Returns:
        A JSON with informations about the Agent
        (like testmodule , pathagent, agentdescriptor, pathimg,
          imgdescriptor, actiontxt, conf and plugins)
    """
    cmd = f'python {os.path.join(xmppobject.pathagent, "replicator.py")} -i -v'
    logger.debug(f"cmd : {cmd}")
    result = simplecommand(cmd)
    resultobj = {}
    rr = [x.rstrip() for x in result["result"]]
    val = [
        "testmodule",
        "pathagent",
        "agentdescriptor",
        "pathimg",
        "imgdescriptor",
        "action",
        "other1",
        "other2",
    ]
    boottrap = 0
    for t in rr:
        if t.startswith("--") or t.startswith("__"):
            continue
        if t.endswith("pulse_xmpp_agent"):
            boottrap = boottrap + 1
        if t.startswith("{"):
            boottrap = boottrap + 1
        if t.startswith("}"):
            resultobj[val[boottrap]].append(t.strip())
            boottrap = boottrap + 1
            continue

        if val[boottrap] not in resultobj:
            resultobj[val[boottrap]] = []
        resultobj[val[boottrap]].append(t.strip())

    testmodule = resultobj["testmodule"][0]
    information = "".join(resultobj["testmodule"][1:])
    agentdescriptor = "".join(resultobj["agentdescriptor"])
    imgdescriptor = "".join(resultobj["imgdescriptor"])
    pathimg = resultobj["pathimg"][0]
    pathagent = resultobj["pathagent"][0]
    actiontxt = ",".join(resultobj["action"])
    res = {
        "testmodule": testmodule,
        "information": information,
        "pathagent": pathagent,
        "agentdescriptor": agentdescriptor,
        "pathimg": pathimg,
        "imgdescriptor": imgdescriptor,
        "actiontxt": actiontxt,
        "conf": xmppobject.config.updating,
        "plugins": xmppobject.dataplugininstall,
    }
    return json.dumps(res, indent=4)


def add_coloring_to_emit_windows(fn):
    # add methods we need to the class
    # def _out_handle(self):
    # import ctypes
    # return ctypes.windll.kernel32.GetStdHandle(self.STD_OUTPUT_HANDLE)
    # out_handle = property(_out_handle)

    def _set_color(self, code):
        import ctypes

        # Constants from the Windows API
        self.STD_OUTPUT_HANDLE = -11
        hdl = ctypes.windll.kernel32.GetStdHandle(self.STD_OUTPUT_HANDLE)
        ctypes.windll.kernel32.SetConsoleTextAttribute(hdl, code)

    setattr(logging.StreamHandler, "_set_color", _set_color)

    def new(*args):
        FOREGROUND_BLUE = 0x0001  # text color contains blue.
        FOREGROUND_GREEN = 0x0002  # text color contains green.
        FOREGROUND_RED = 0x0004  # text color contains red.
        FOREGROUND_INTENSITY = 0x0008  # text color is intensified.
        FOREGROUND_WHITE = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED
        # winbase.h
        # STD_INPUT_HANDLE = -10
        # STD_OUTPUT_HANDLE = -11
        # STD_ERROR_HANDLE = -12

        # wincon.h
        # FOREGROUND_BLACK     = 0x0000
        FOREGROUND_BLUE = 0x0001
        FOREGROUND_GREEN = 0x0002
        # FOREGROUND_CYAN      = 0x0003
        FOREGROUND_RED = 0x0004
        FOREGROUND_MAGENTA = 0x0005
        FOREGROUND_YELLOW = 0x0006
        # FOREGROUND_GREY      = 0x0007
        FOREGROUND_INTENSITY = 0x0008  # foreground color is intensified.

        # BACKGROUND_BLACK     = 0x0000
        # BACKGROUND_BLUE      = 0x0010
        # BACKGROUND_GREEN     = 0x0020
        # BACKGROUND_CYAN      = 0x0030
        # BACKGROUND_RED       = 0x0040
        # BACKGROUND_MAGENTA   = 0x0050
        BACKGROUND_YELLOW = 0x0060
        # BACKGROUND_GREY      = 0x0070
        BACKGROUND_INTENSITY = 0x0080  # background color is intensified.

        levelno = args[1].levelno
        if levelno >= 50:
            color = (
                BACKGROUND_YELLOW
                | FOREGROUND_RED
                | FOREGROUND_INTENSITY
                | BACKGROUND_INTENSITY
            )
        elif levelno >= 40:
            color = FOREGROUND_RED | FOREGROUND_INTENSITY
        elif levelno >= 30:
            color = FOREGROUND_YELLOW | FOREGROUND_INTENSITY
        elif levelno >= 20:
            color = FOREGROUND_GREEN
        elif levelno >= 10:
            color = FOREGROUND_MAGENTA
        else:
            color = FOREGROUND_WHITE
        args[0]._set_color(color)

        ret = fn(*args)
        args[0]._set_color(FOREGROUND_WHITE)
        # print "after"
        return ret

    return new


def add_coloring_to_emit_ansi(fn):
    # add methods we need to the class
    def new(*args):
        levelno = args[1].levelno
        if levelno >= 50:
            color = "\x1b[31m"  # red
        elif levelno >= 40:
            color = "\x1b[31m"  # red
        elif levelno >= 30:
            color = "\x1b[33m"  # yellow
        elif levelno >= 20:
            color = "\x1b[32m"  # green
        elif levelno >= 10:
            color = "\x1b[35m"  # pink
        else:
            color = "\x1b[0m"  # normal
        args[1].msg = color + str(args[1].msg) + "\x1b[0m"  # normal
        # print "after"
        return fn(*args)

    return new


def directoryconffile():
    """
    This function provide the path to the configuration files of pulse-xmpp-agent.

    Return:
        it returns the path to the configuration files if it exists
        it returns None if the path does not exist
    """
    if sys.platform.startswith("linux"):
        fileconf = os.path.join("/", "etc", "pulse-xmpp-agent")
    elif sys.platform.startswith("win"):
        fileconf = os.path.join(os.environ["ProgramFiles"], "Pulse", "etc")
    elif sys.platform.startswith("darwin"):
        fileconf = os.path.join("/opt", "Pulse", "etc")
    return fileconf if os.path.isdir(fileconf) else None


def refreshfingerprint():
    fp = createfingerprintnetwork()
    file_put_contents(os.path.join(Setdirectorytempinfo(), "fingerprintnetwork"), fp)
    return fp


def simplecommandstr(cmd):
    if isinstance(cmd, bytes):
        cmd = decode_strconsole(cmd)
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    obj = {"result": "", "code": p.wait()}
    result = p.stdout.readlines()
    if sys.version_info[0] == 3:
        result = [decode_strconsole(x) for x in result]
    else:
        result = list(result)
    obj["result"] = "".join(result)
    return obj


def decode_strconsole(x):
    """
    Decode strings into the format used on the OS.
    Supported OS are: linux, windows and darwin

    Args:
        x: the string we want to encode

    Returns:
        The decoded `x` string
    """

    if sys.platform.startswith("linux"):
        return x.decode("utf-8", "ignore")

    if sys.platform.startswith("win"):
        return x.decode("cp850", "ignore")

    return x.decode("utf-8", "ignore") if sys.platform.startswith("darwin") else x


def simplecommand(cmd, emptyline=True):
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    result = p.stdout.readlines()
    obj = {"code": p.wait()}
    if emptyline:
        obj["result"] = [x.strip("\n") for x in result if x.strip() != ""]
    else:
        obj["result"] = result
    return obj


def file_get_contents(filename, use_include_path=0, context=None, offset=-1, maxlen=-1):
    if filename.find("://") > 0:
        ret = urllib.request.urlopen(filename).read()
        if offset > 0:
            ret = ret[offset:]
        if maxlen > 0:
            ret = ret[:maxlen]
        return ret
    else:
        fp = open(filename, "rb")
        try:
            if offset > 0:
                fp.seek(offset)
            return fp.read(maxlen)
        finally:
            fp.close()


def refreshfingerprintconf(typeconf):
    fp = createfingerprintconf(typeconf)
    file_put_contents(os.path.join(Setdirectorytempinfo(), "fingerprintconf"), fp)
    return fp


def confinfoexist():
    filenetworkinfo = os.path.join(Setdirectorytempinfo(), "fingerprintconf")
    return bool(os.path.exists(filenetworkinfo))


def confchanged(typeconf):
    if confinfoexist():
        fingerprintconf = file_get_contents(
            os.path.join(Setdirectorytempinfo(), "fingerprintconf")
        )
        newfingerprintconf = createfingerprintconf(typeconf)
        if newfingerprintconf == fingerprintconf:
            return False
    return True


def createfingerprintconf(typeconf):
    namefileconfig = conffilename(typeconf)
    return hashlib.md5(file_get_contents(namefileconfig)).hexdigest()


def file_put_contents(filename, data):
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    with open(filename, "w") as f:
        f.write(data)


def Setdirectorytempinfo():
    """
    This functions create a temporary directory.

    @returns path directory INFO Temporaly and key RSA
    """
    dirtempinfo = os.path.join(os.path.dirname(os.path.realpath(__file__)), "INFOSTMP")
    if not os.path.exists(dirtempinfo):
        os.makedirs(dirtempinfo, mode=0o007)
    return dirtempinfo


def createfingerprintnetwork():
    md5network = ""
    if sys.platform.startswith("win"):
        obj = simplecommandstr("ipconfig")
        md5network = hashlib.md5(obj["result"].encode("utf-8")).hexdigest()
    elif sys.platform.startswith("linux"):
        # voir pour remplacer par  ip address | grep inet | grep -v inet6
        obj = simplecommandstr(
            "LANG=C ifconfig | egrep '.*(inet|HWaddr).*' | grep -v inet6"
        )
        md5network = hashlib.md5(obj["result"].encode("utf-8")).hexdigest()
    elif sys.platform.startswith("darwin"):
        obj = simplecommandstr("ipconfig")
        md5network = hashlib.md5(obj["result"].encode("utf-8")).hexdigest()
    return md5network


def networkinfoexist():
    """
    This function checks if the fingerprintnetwork file exists.

    Returns:
        it returns True if the file exists. False otherwise
    """
    filenetworkinfo = os.path.join(Setdirectorytempinfo(), "fingerprintnetwork")
    return bool(os.path.exists(filenetworkinfo))


def networkchanged():
    if not networkinfoexist():
        return True
    fingerprintnetwork = file_get_contents(
        os.path.join(Setdirectorytempinfo(), "fingerprintnetwork")
    )
    newfingerprint = createfingerprintnetwork()
    if fingerprintnetwork == newfingerprint:
        return False


def conffilename(agenttype):
    """
    This function define where the configuration file is located.

    Args:
        agenttype: type of the agent, relay or machine or cluster for RelayServer

    Returns:
        Return the config file path

    """
    if agenttype in ["machine"]:
        conffilenameparameter = "agentconf.ini"
    elif agenttype in ["cluster"]:
        conffilenameparameter = "cluster.ini"
    else:
        conffilenameparameter = "relayconf.ini"

    if directoryconffile() is not None:
        fileconf = os.path.join(directoryconffile(), conffilenameparameter)
    else:
        fileconf = conffilenameparameter

    if conffilenameparameter == "cluster.ini":
        return fileconf

    return fileconf if os.path.isfile(fileconf) else conffilenameparameter


def testagentconf(typeconf):
    if typeconf == "relayserver":
        return True
    Config = configparser.ConfigParser()
    namefileconfig = conffilename(typeconf)
    Config.read(namefileconfig)
    return bool(
        (
            Config.has_option("type", "guacamole_baseurl")
            and Config.has_option("connection", "port")
            and Config.has_option("connection", "server")
            and Config.has_option("global", "relayserver_agent")
            and Config.get("type", "guacamole_baseurl") != ""
            and Config.get("connection", "port") != ""
            and Config.get("connection", "server") != ""
            and Config.get("global", "relayserver_agent") != ""
        )
    )


def isTemplateConfFile(typeconf):
    """
    Test the configuration file to see if this is a valid template file.
    Args:
        typeconf: Type of the agent (machine, relayserver)

    Returns:
        It returns True if this is a relayserver or a valid template file.
    """
    if typeconf == "relayserver":
        return True
    Config = configparser.ConfigParser()
    namefileconfig = conffilename(typeconf)
    Config.read(namefileconfig)
    return bool(
        (
            Config.has_option("configuration_server", "confserver")
            and Config.has_option("configuration_server", "confport")
            and Config.has_option("configuration_server", "confpassword")
            and Config.has_option("configuration_server", "confdomain")
            and Config.get("configuration_server", "keyAES32") != ""
        )
    )


def programfilepath(pathwindows):
    """
    Normalise le chemin de fichier `pathwindows` pour le système d'exploitation Windows.

    Arguments:
        pathwindows (str): Le chemin de fichier à normaliser.

    Returns:
        str: Le chemin de fichier normalisé pour Windows.

    Remarque:
        La fonction prend un chemin de fichier `pathwindows` en entrée et le normalise pour
        le système d'exploitation Windows en remplaçant les barres obliques inverses par des
        doubles barres obliques et en encadrant les noms de répertoires contenant des espaces par des guillemets.

        Cette normalisation est particulièrement utile lorsque vous devez manipuler des chemins de fichiers avec
        des espaces dans les noms de répertoires sur Windows.

    Exemple:
        >>> programfilepath("C:/chemin avec des espaces/fichier.txt")
        'C:\\chemin avec des espaces\\fichier.txt'
        >>> programfilepath("C:/chemin/sans/espaces/fichier.txt")
        'C:\\chemin\\sans\\espaces\\fichier.txt'
        >>> programfilepath("D:/répertoire avec espace/")
        'D:\\répertoire avec espace'
        >>> programfilepath("D:/répertoire_sans_espaces/")
        'D:\\répertoire_sans_espaces'
    """
    if sys.platform.startswith("win"):
        pathwindows = os.path.normpath(pathwindows)
        disk_path = pathwindows.split(":")
        if len(disk_path) < 2:
            return pathwindows
        disk = disk_path.pop(0) + ":" + "\\\\"
        pathdir = "".join(disk_path)
        t = [x.strip('" ') for x in pathdir.split("\\") if x.strip('" ') != ""]
        result = []
        for x in t:
            if " " in x:
                result.append('"' + x + '"')
            else:
                result.append(x)
        return disk + "\\\\".join(result)
    return pathwindows


def start_agent(pathagent, agent="connection", console=False, typeagent="machine"):
    pythonexec = programfilepath(psutil.Process().exe())
    agentfunction = os.path.join(pathagent, "connectionagent.py")

    if agent != "connection":
        agentfunction = os.path.join(pathagent, "agentxmpp.py")
    agentfunction = programfilepath(agentfunction)
    modeagent = " -c " if console else ""
    logger.debug(f"AGENT {agent}")
    if agent == "connection":
        logger.debug("Starting configuration agent")

        if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
            logger.debug(
                f"launcher for os system  {pythonexec} {agentfunction}{modeagent} -t {typeagent}"
            )
            os.system(f"{pythonexec} {agentfunction}{modeagent} -t {typeagent}")
        else:
            logger.debug(
                f"launcher for os windows system {pythonexec}  {agentfunction}{modeagent} -t {typeagent}"
            )
            os.system(f"{pythonexec} {agentfunction}{modeagent} -t {typeagent}")
        logger.debug(
            "Refreshing fingerprint of configuration agent after its reconfiguration"
        )
        refreshfingerprintconf("machine")
    else:
        logger.debug("start agent machine ")
        ProcessData = global_data_process()
        ProcessData.start_process_agent(
            [pythonexec, agentfunction, modeagent, "-t", typeagent]
        )
        logger.debug(
            "start agent %s" % [pythonexec, agentfunction, modeagent, "-t", typeagent]
        )


if __name__ == "__main__":
    start_time = datetime.now()
    ProcessData = global_data_process()

    if platform.system() == "Windows":
        # Windows does not support ANSI escapes and we are using API calls to set the console color
        logging.StreamHandler.emit = add_coloring_to_emit_windows(
            logging.StreamHandler.emit
        )
    else:
        # all non-Windows platforms are supporting ANSI escapes so we use them
        logging.StreamHandler.emit = add_coloring_to_emit_ansi(
            logging.StreamHandler.emit
        )

    # format log more informations
    format = "%(asctime)s - %(levelname)s - (LAUNCHER)%(message)s"

    directory_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "INFOSTMP"
    )

    BOOL_FILE_CONTROL_WATCH_DOG = os.path.join(
        directory_file, "BOOL_FILE_CONTROL_WATCH_DOG"
    )
    if os.path.isfile(BOOL_FILE_CONTROL_WATCH_DOG):
        os.remove(BOOL_FILE_CONTROL_WATCH_DOG)

    file_put_contents(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "INFOSTMP", "pidlauncher"
        ),
        "%s" % os.getpid(),
    )

    if sys.platform.startswith("win"):
        try:
            result = subprocess.check_output(
                [
                    "icacls",
                    os.path.join(
                        os.path.dirname(os.path.realpath(__file__)),
                        "INFOSTMP",
                        "pidlauncher",
                    ),
                    "/setowner",
                    "pulseuser",
                    "/t",
                ],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            pass
    optp = OptionParser()
    optp.add_option(
        "-t",
        "--type",
        dest="typemachine",
        default=False,
        help="Type machine: machine or relayserver",
    )

    optp.add_option(
        "-c",
        "--consoledebug",
        action="store_true",
        dest="consoledebug",
        default=False,
        help="console debug",
    )

    opts, args = optp.parse_args()

    if opts.typemachine.lower() in ["machine"]:
        defaultnamelogfile = "xmpp-agent-machine.log"
    else:
        defaultnamelogfile = "xmpp-agent-relay.log"

    if sys.platform.startswith("win"):
        logfile = os.path.join(
            os.environ["ProgramFiles"], "Pulse", "var", "log", defaultnamelogfile
        )
    elif sys.platform.startswith("darwin"):
        logfile = os.path.join("/opt", "Pulse", "var", "log", defaultnamelogfile)
    else:
        logfile = os.path.join("/", "var", "log", "pulse", defaultnamelogfile)
    if opts.consoledebug:
        logging.basicConfig(level=logging.DEBUG, format=format)
    else:
        mfile = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "DEBUG_LAUNCHER"
        )
        if os.path.isfile(mfile):
            LOGMODE = logging.DEBUG
        else:
            LOGMODE = logging.INFO
        logging.basicConfig(
            level=LOGMODE, format=format, filename=logfile, filemode="a"
        )

    if sys.platform.startswith("win"):
        result = win32api.SetConsoleCtrlHandler(ProcessData._CtrlHandler, 1)
        if result == 0:
            logger.debug(
                "Could not SetConsoleCtrlHandler (error %r)" % win32api.GetLastError()
            )
        else:
            logger.debug("Set handler for console events.")
    elif sys.platform.startswith("linux"):
        signal.signal(signal.SIGINT, ProcessData.signal_handler)
        signal.signal(signal.SIGQUIT, ProcessData.signal_handler)

    logger.debug("Starting the launcher")

    if not opts.typemachine.lower() in ["machine", "relayserver"]:
        logger.error(
            "The parameter for the -t option is wrong. It must be machine or relayserver"
        )
        sys.exit(1)

    namefileconfig = conffilename(opts.typemachine)
    if not os.path.isfile(namefileconfig):
        # The pulseagent config file is missing. We need to reinstall the rescue.
        logger.debug(
            "The configuration file %s is missing. Trying to reinstall the rescue agent."
            % namefileconfig
        )
        ret = install_rescue_image().reinstall_agent_rescue()

    # first start network changed
    networkchanged = networkchanged()
    needreconfiguration = False

    if not networkchanged and not testagentconf(opts.typemachine):
        logger.debug(
            "Some configuration options are missing. You may need to add guacamole_baseurl connection/port/server' or global/relayserver_agent"
        )
        logger.debug("We need to reconfigure")
        testconfigurable = isTemplateConfFile(opts.typemachine)
        if testconfigurable:
            needreconfiguration = True
        else:
            ret = install_rescue_image().reinstall_agent_rescue()

    if networkchanged:
        logger.debug("We detected modifications in the network configuration.")
        refreshfingerprint()

    configchanged = confchanged(opts.typemachine)
    if configchanged:
        logger.info("We detected modifications in the configuration")
        refreshfingerprintconf(opts.typemachine)

    BOOL_FILE_INSTALL = os.path.join(filePath, "BOOL_FILE_INSTALL")
    if os.path.isfile(BOOL_FILE_INSTALL):
        os.remove(BOOL_FILE_INSTALL)
        needreconfiguration = True

    if networkchanged or configchanged or needreconfiguration:
        logger.info("We start a reconfiguration of the medulla agent")

    testagenttype = testagentconf(opts.typemachine)

    testspeedagent = (
        networkchanged or configchanged or not testagenttype or needreconfiguration
    )

    path_reconf_nomade = os.path.join(filePath, "BOOL_FILE_ALWAYSNETRECONF")
    if os.path.exists(path_reconf_nomade):
        testspeedagent = True
        logger.debug(
            "The file %s exists. We will reconfigure at every start"
            % path_reconf_nomade
        )

    pathagent = os.path.join(os.path.dirname(os.path.realpath(__file__)))

    launcher = os.path.join(pathagent, "launcher.py")
    connectionagent = os.path.join(pathagent, "connectionagent.py")
    agentxmpp = os.path.join(pathagent, "agentxmpp.py")

    pythonexec = psutil.Process().exe()
    # pythonexec = "C:\\Program\ Files\\Python39\\python.exe"
    os.chdir(pathagent)

    if ProcessData.terminate_process:
        logger.debug("Quit program")
        sys.exit(0)

    if opts.typemachine.lower() in ["machine"]:
        if testspeedagent:
            logger.debug("Launching the configurator agent")
            start_agent(pathagent, agent="connection", console=opts.consoledebug)

    if ProcessData.terminate_process:
        logger.debug("Quit program")
        sys.exit(0)

    start_agent(
        pathagent, agent="am", console=opts.consoledebug, typeagent=opts.typemachine
    )

    if ProcessData.terminate_process:
        logger.debug("Quit program")
        sys.exit(0)
    test = 1
    time.sleep(20)
    try:
        rescue_image = create_rescue_agent()
        if not rescue_image.info._exist_rescue():
            # We create the rescue image if it does not exist yet.
            rescue_image.save_rescue_src()
    except:
        logger.error("\n%s" % (traceback.format_exc()))

    update_rescue_on_stabilisation = False
    countcycle = 1
    while 1:
        if ProcessData.terminate_process:
            logger.debug("Quit program on event")
            break

        ProcessData.is_alive()
        ProcessData.load_child_process()
        try:
            end_time = datetime.now()
            logger.debug("time progam on: {}".format(end_time - start_time))
            logger.debug("### LOOP LAUNCHER CYCLE %s###" % countcycle)
            if (countcycle % 6) == 0:  # Every 60 secondes.
                if sys.platform.startswith("linux") or sys.platform.startswith(
                    "darwin"
                ):
                    # Actions to proceed on the Linux server
                    # FIXME: Really needed ?
                    logger.debug("monitoring memoire linux")
                    ret = simplecommand("free -m")
                    re = [("%s\n") % x for x in ret["result"] if x != ""]
                    res = "".join(re)
                    logger.debug("\n%s" % res)
                    ret = simplecommand("mpstat -P ALL")
                    re = [("%s\n") % x for x in ret["result"] if x != ""]
                    res = "".join(re)
                    logger.debug("\n%s" % res)

            if (countcycle % 18) == 0:  # Every 180 seconds
                ProcessData.display_Process()
                if os.path.isfile(BOOL_FILE_CONTROL_WATCH_DOG):
                    data_file = file_get_contents(BOOL_FILE_CONTROL_WATCH_DOG)
                    # No problems found. We remove the Watchdog file.
                    os.remove(BOOL_FILE_CONTROL_WATCH_DOG)
                    if not update_rescue_on_stabilisation and os.path.isfile(
                        namefileconfig
                    ):
                        if testagentconf(opts.typemachine):
                            try:
                                logger.info(
                                    "We are saving the current agent into the rescue copy."
                                )
                                rescue_image = create_rescue_agent().save_rescue_src()
                                update_rescue_on_stabilisation = True
                                logger.info("The copy of the rescue agent is finished.")
                            except:
                                logger.error(
                                    "We hit a backtrace when saving the rescue agent \n %s"
                                    % traceback.format_exc()
                                )
                        else:
                            logger.error(
                                "We cannot save the rescue copy. Something went wrong."
                            )
                else:
                    # probleme sur agent. reinstalle rescue
                    # We stop the agent.
                    ProcessData.stop_process_agent()
                    logger.debug(
                        "We are reinstalling the agent thanks to the rescue image"
                    )
                    ret = install_rescue_image().reinstall_agent_rescue()
                    logger.debug("The rescue is done, now We start a reconfiguration")
                    if opts.typemachine.lower() in ["machine"]:
                        start_agent(
                            pathagent, agent="connection", console=opts.consoledebug
                        )
                    # We could start the rescue agent with specific actions
                    # Even if the agent is not in a good state.
                    # Not yet implemented.
                    logger.debug("We restart the Agent")
                    start_agent(
                        pathagent,
                        agent="am",
                        console=opts.consoledebug,
                        typeagent=opts.typemachine,
                    )
            else:
                pass
        except:
            logger.error("\n%s" % (traceback.format_exc()))
        countcycle = countcycle + 1
        time.sleep(10)
    ProcessData.stop_process_agent()
    time.sleep(1)
