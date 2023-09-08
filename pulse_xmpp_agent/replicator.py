#!/usr/bin/python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


"""
    Allow to create a copy of the actual agent.
    WARNING: This software MUST BE in the same folder as the actual agent.
"""
import os
import sys
import logging
import json
import hashlib
import shutil
import importlib
import urllib

from optparse import OptionParser

if sys.platform.startswith("win"):
    import winreg


def copytree2(src, dst, symlinks=False):
    names = os.listdir(src)
    try:
        os.makedirs(dst)
    except BaseException:
        pass
    errors = []
    ignore1 = [
        "descriptor_scheduler_relay",
        "fifodeploy",
        "img_agent",
        "INFOSTMP",
        "pluginsmachine",
        "pluginsrelay",
        "sessionsrelayserver",
    ]

    for name in names:
        if name in ignore1:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if symlinks and os.path.islink(srcname):
                linkto = os.readlink(srcname)
                os.symlink(linkto, dstname)
            elif os.path.isdir(srcname):
                copytree2(srcname, dstname, symlinks)
            elif not srcname.endswith(".pyc"):
                shutil.copy2(srcname, dstname)
                # XXX What about devices, sockets etc.?
        except (IOError, os.error) as why:
            errors.append((srcname, dstname, str(why)))
        except Exception as err:
            errors.extend(err.args[0])
    try:
        shutil.copystat(src, dst)
    except shutil.WindowsError:
        # can't copy file access times on Windows
        pass
    except OSError as why:
        errors.extend((src, dst, str(why)))
    return not errors


def search_action_on_agent_cp_and_del(fromimg, frommachine):
    """
    return 2 lists
    list files to copi from img to mach
    list files to supp in mach
    """
    replace_file_mach_by_file_img = []
    file_supp_in_mach = []
    # il y aura 1 ou plusieurs fichier a supprimer dans l'agent.
    # search fiichier devenu inutile
    for namefichier in frommachine:
        if namefichier in fromimg:
            # fichier dans les 2 cotes
            # on verifie si on doit remplacer:
            if frommachine[namefichier] != fromimg[namefichier]:
                # on doit le remplacer
                replace_file_mach_by_file_img.append(namefichier)
        else:
            file_supp_in_mach.append(namefichier)
    file_missing_in_mach = [
        namefichier for namefichier in fromimg if namefichier not in frommachine
    ]
    # les fichiers manquant dans machine sont aussi des fichier a rajouter.
    fichier_to_copie = list(replace_file_mach_by_file_img)
    fichier_to_copie.extend(file_missing_in_mach)
    return fichier_to_copie, file_supp_in_mach


def install_key_register_windows(version):
    if sys.platform.startswith("win"):
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Medulla Agent\\",
                0,
                winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
            )
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, version.strip())
            winreg.CloseKey(key)
        except Exception as e:
            return False
    return True


def file_get_contents(filename, use_include_path=0, context=None, offset=-1, maxlen=-1):
    if filename.find("://") > 0:
        ret = urllib.request.urlopen(filename).read()
        if offset > 0:
            ret = ret[offset:]
        if maxlen > 0:
            ret = ret[:maxlen]
        return ret
    else:
        fp = open(filename, "r")
        try:
            if offset > 0:
                fp.seek(offset)
            return fp.read(maxlen)
        finally:
            fp.close()


def file_get_binarycontents(filename, offset=-1, maxlen=-1):
    fp = open(filename, "rb")
    try:
        if offset > 0:
            fp.seek(offset)
        return fp.read(maxlen)
    finally:
        fp.close()


class Update_Remote_Agent:
    """
    this class calculates the fingerprint of the agent.
    Param : dir_agent_base is the location of agent
    Param : autoupdate is the switch for enabling or disabling remote update.
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
        # verify exist dir and create si not exit. The default mode is 0777
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
                    f"Creating folder for remote base agent : {dir_agent_base}"
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


def restorationfolder(rollback_pulse_xmpp_agent, agent_folder):
    copytree2(rollback_pulse_xmpp_agent, agent_folder)
    shutil.rmtree(rollback_pulse_xmpp_agent)


def install_direct(agent_image, agent_folder):
    return copytree2(agent_image, agent_folder)


def prepare_folder_rollback(rollback_pulse_xmpp_agent, agent_folder):
    # creation folder sauvegarde for save file supp
    try:
        os.makedirs(rollback_pulse_xmpp_agent)
    except OSError:
        # directory already exists
        pass
    shutil.rmtree(rollback_pulse_xmpp_agent)
    copytree2(agent_folder, rollback_pulse_xmpp_agent)


def module_needed(agent_image, verbose=False):
    # sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__))))
    # create file __init.py si non exist
    boolfichier = False
    error = False
    initfile = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "img_agent", "__init__.py"
    )
    if not os.path.isfile(initfile):
        boolfichier = True
        open(initfile, "w").close()
    list_script_python_for_update = [
        "agentxmpp.py",
        "launcher.py",
        "connectionagent.py",
        "replicator.py",
    ]
    for filename in list_script_python_for_update:
        try:
            importlib.import_module(f"img_agent.{filename[:-3]}")
        except Exception as e:
            if verbose:
                print(
                    f'Some python modules needed for running "{filename}" are missing. We will not switch to new agent'
                )
                error = True
    if boolfichier:
        try:
            os.remove(initfile)
        except BaseException:
            print("Error while deleting file __init__.py")
    if error:
        return False

    for filename in [
        x[:-3]
        for x in os.listdir(os.path.join(agent_image, "lib"))
        if x.endswith(".py")
    ]:
        try:
            importlib.import_module(f"img_agent.lib.{filename}")
        except ImportError:
            if verbose:
                print(
                    f"Some python modules needed for running lib/{filename} are missing. We will not switch to new agent"
                )
            return False
    return True


if __name__ == "__main__":
    # execute only if run as a script
    # ce programme doit repliquer un agent image to l'emplacement de l'agent.
    # ce programme doit faire un rooll back si une opération pose probleme.
    # ce programme agit si certaine fichier boolean existe.

    # return  0 rien a faire agent deja installe
    # return  1 agent installe correctement et injection de la key de registre windows
    # return 120 agent non installer discriptor rétablie agent par rollback
    # return 121 agent installer mais pas reussi a installer la key de
    # registre pour windows.
    parser = OptionParser()

    parser.add_option(
        "-v",
        "--verbose",
        action="store_true",
        dest="verbose",
        default=False,
        help="print status messages to stdout",
    )
    parser.add_option(
        "-i",
        "--info",
        action="store_true",
        dest="info",
        default=False,
        help="print information to stdout ('not replicator')",
    )

    (options, args) = parser.parse_args()
    pathagent = os.path.join(os.path.dirname(os.path.realpath(__file__)))
    img_agent = os.path.join(os.path.dirname(os.path.realpath(__file__)), "img_agent")

    # First check if machine has all necessary python modules to load image
    if not module_needed(img_agent, verbose=(options.verbose or options.info)):
        if options.verbose or options.info:
            print("KO: missing python modules in image")
        else:
            sys.exit(122)
    elif options.verbose or options.info:
        print("OK: no missing python modules in image")

    # folder for save file supp
    rollback_pulse_xmpp_agent = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "..",
            "rollback_pulse_xmpp_agent",
        )
    )

    prepare_folder_rollback(rollback_pulse_xmpp_agent, pathagent)

    objdescriptoragent = Update_Remote_Agent(pathagent, True)
    objdescriptorimage = Update_Remote_Agent(img_agent)

    descriptoragent = objdescriptoragent.get_md5_descriptor_agent()
    descriptorimage = objdescriptorimage.get_md5_descriptor_agent()
    if options.verbose or options.info:
        print("--------------------------------------------")
        if descriptoragent["fingerprint"] != descriptorimage["fingerprint"]:
            print("The fingerprints are different between the agent and the image")
        else:
            print("The fingerprints are the same between the agent and the image")
        print("--------------------------------------------")
        if descriptoragent["version"] != descriptorimage["version"]:
            print("The versions are different between the agent and the image")
        else:
            print("The versions are the same between the agent and the image")
        print("--------------------------------------------")
        print(objdescriptoragent.dir_agent_base)
        print(json.dumps(descriptoragent, indent=4))
        print("--------------------------------------------")
        print(objdescriptorimage.dir_agent_base)
        print(json.dumps(descriptorimage, indent=4))
        print("--------------------------------------------")
    boolinstalldirect = True
    if descriptorimage["fingerprint"] == descriptoragent["fingerprint"]:
        if options.verbose or options.info:
            print("No UPDATING, no diff between agent and agentimage")
            print("Agent up to date")
        sys.exit(0)
    else:
        try:
            for directory_agent in descriptoragent:
                if directory_agent in ["fingerprint", "version", "version_agent"]:
                    continue
                # search les differences.
                diff, supp = search_action_on_agent_cp_and_del(
                    descriptorimage[directory_agent], descriptoragent[directory_agent]
                )
                if directory_agent == "program_agent":
                    dirname = ""
                elif directory_agent == "lib_agent":
                    dirname = "lib"
                elif directory_agent == "script_agent":
                    dirname = "script"
                diff2 = [os.path.join(pathagent, dirname, x) for x in diff]
                supp2 = [os.path.join(pathagent, dirname, x) for x in supp]
                if options.verbose or options.info:
                    if supp2 or diff2:
                        print(
                            "_______________________________________________________________________________________________"
                        )
                        print(f"Action for {directory_agent}")
                    if diff2:
                        print("Replace or add agent files")
                        print(json.dumps(diff2, indent=4, sort_keys=True))
                    if supp2:
                        print("Unused agent file")
                        print(json.dumps(supp2, indent=4, sort_keys=True))
                if not options.info:
                    for delfile in supp2:
                        os.remove(delfile)
            if options.info:
                # info information sans replicator
                sys.exit(5)
        except BaseException:
            boolinstalldirect = False
        if not options.info:
            if boolinstalldirect:
                if not install_direct(img_agent, pathagent):
                    restorationfolder(rollback_pulse_xmpp_agent, pathagent)
                    sys.exit(120)
                version = file_get_contents(
                    os.path.join(img_agent, "agentversion")
                ).strip()
                if not install_key_register_windows(version):
                    sys.exit(121)
                sys.exit(1)
            else:
                restorationfolder(rollback_pulse_xmpp_agent, pathagent)
                sys.exit(120)
