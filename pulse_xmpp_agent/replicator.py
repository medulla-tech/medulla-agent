#!/usr/bin/env python3
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
import subprocess

from pathlib import Path

from optparse import OptionParser, SUPPRESS_HELP

if sys.platform.startswith("win"):
    import winreg

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"


IGNORE_AGENT_IMAGE_ENTRIES = [
    "descriptor_scheduler_relay",
    "fifodeploy",
    "img_agent",
    "INFOSTMP",
    "pluginsmachine",
    "pluginsrelay",
    "sessionsrelayserver",
]


def copytree2(src, dst, symlinks=False, force=False):
    BOOL_DISABLE_IMG = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "BOOL_DISABLE_IMG"
    )
    if os.path.exists(BOOL_DISABLE_IMG) and not force:
        return
    names = os.listdir(src)
    try:
        os.makedirs(dst)
    except BaseException:
        pass
    errors = []

    for name in names:
        if name in IGNORE_AGENT_IMAGE_ENTRIES:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if symlinks and os.path.islink(srcname):
                linkto = os.readlink(srcname)
                os.symlink(linkto, dstname)
            elif os.path.isdir(srcname):
                copytree2(srcname, dstname, symlinks, force=force)
            elif not srcname.endswith(".pyc"):
                shutil.copy2(srcname, dstname)
                # XXX What about devices, sockets etc.?
        except IOError as why:
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


def iter_supported_image_files(src, dst):
    for name in sorted(os.listdir(src)):
        if name in IGNORE_AGENT_IMAGE_ENTRIES:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        if os.path.isdir(srcname):
            yield from iter_supported_image_files(srcname, dstname)
        elif not srcname.endswith(".pyc"):
            yield srcname, dstname


def print_dry_run_copy_plan(agent_image, agent_folder):
    if not os.path.isdir(agent_image):
        print(f"DRY-RUN: image folder missing: {agent_image}")
        return False
    count = 0
    for srcname, dstname in iter_supported_image_files(agent_image, agent_folder):
        count += 1
        print(f"COPY {srcname} -> {dstname}")
    print(f"DRY-RUN: {count} file(s) would be copied from image")
    return True


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


def file_get_contents(
    filename, use_include_path=0, context=None, offset=-1, maxlen=-1, encoding=None
):
    if isinstance(filename, bytes):
        filename = filename.decode()

    print(filename)
    if filename.find("://") > 0:
        ret = urllib.request.urlopen(filename).read()
        if offset > 0:
            ret = ret[offset:]
        if maxlen > 0:
            ret = ret[:maxlen]
        return ret
    else:
        if encoding:
            fp = open(filename, "r", encoding=encoding)
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
                    f"Replicator: Creating folder for remote base agent : {dir_agent_base}"
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
            self.directory["version"].encode("utf-8")
        ).hexdigest()
        listmd5 = [self.directory["version_agent"]]
        list_script_python_for_update = [
            "agentxmpp.py",
            "launcher.py",
            "connectionagent.py",
            "replicator.py",
        ]

        for filename in list_script_python_for_update:
            self.directory["program_agent"][filename] = hashlib.md5(
                file_get_binarycontents(os.path.join(self.dir_agent_base, filename))
            ).hexdigest()
            listmd5.append(self.directory["program_agent"][filename])
        for filename in [
            x
            for x in os.listdir(os.path.join(self.dir_agent_base, "lib"))
            if x[-3:] == ".py"
        ]:
            self.directory["lib_agent"][filename] = hashlib.md5(
                file_get_binarycontents(
                    os.path.join(self.dir_agent_base, "lib", filename)
                )
            ).hexdigest()
            listmd5.append(self.directory["lib_agent"][filename])
        # IMPORTANT: Les fichiers .py DOIVENT être inclus car ce descripteur est envoyé aux agents.
        # Sans cette inclusion, les scripts Python du dossier script/ ne seraient jamais synchronisés.
        for filename in [
            x
            for x in os.listdir(os.path.join(self.dir_agent_base, "script"))
            if x.endswith((".ps1", ".py"))
        ]:
            self.directory["script_agent"][filename] = hashlib.md5(
                file_get_binarycontents(
                    os.path.join(self.dir_agent_base, "script", filename)
                )
            ).hexdigest()
            listmd5.append(self.directory["script_agent"][filename])
        listmd5.sort()
        self.directory["fingerprint"] = hashlib.md5(
            json.dumps(listmd5).encode("utf-8")
        ).hexdigest()


def restorationfolder(rollback_pulse_xmpp_agent, agent_folder):
    copytree2(rollback_pulse_xmpp_agent, agent_folder)
    shutil.rmtree(rollback_pulse_xmpp_agent)


def install_direct(agent_image, agent_folder, force=False):
    return copytree2(agent_image, agent_folder, force=force)


def resolve_agent_paths():
    script_folder = os.path.dirname(os.path.realpath(__file__))
    if os.path.basename(script_folder) == "img_agent":
        return os.path.dirname(script_folder), script_folder
    return script_folder, os.path.join(script_folder, "img_agent")


def launch_detached_force_run(verbose=False):
    replicator = os.path.realpath(__file__)
    command = [sys.executable, replicator, "--force-run"]
    if verbose:
        command.append("--verbose")
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    creationflags = 0
    start_new_session = False
    if sys.platform.startswith("win"):
        creationflags |= subprocess.DETACHED_PROCESS
        creationflags |= subprocess.CREATE_NEW_PROCESS_GROUP
        creationflags |= getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)
    else:
        start_new_session = True
    subprocess.Popen(
        command,
        cwd=os.path.dirname(replicator),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creationflags,
        start_new_session=start_new_session,
        env=env,
    )


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
    original_sys_path = sys.path.copy()
    error = False

    img_agent_path = Path(agent_image)
    sys.path = [p for p in sys.path if "pulse_xmpp_agent" not in p]
    sys.path.insert(0, str(img_agent_path))

    list_script_python_for_update = [
        "agentxmpp.py",
        "launcher.py",
        "connectionagent.py",
        "replicator.py",
    ]
    for filename in list_script_python_for_update:
        try:
            importlib.import_module(f"{filename[:-3]}")
        except Exception as e:
            if verbose:
                print(
                    f'Some python modules needed for running "{filename}" are missing. We will not switch to new agent'
                )
            error = True
    if error:
        sys.path = original_sys_path
        return False

    for filename in [
        x[:-3]
        for x in os.listdir(os.path.join(agent_image, "lib"))
        if x.endswith(".py")
    ]:
        try:
            importlib.import_module(f"lib.{filename}")
        except ImportError:
            if verbose:
                print(
                    f"Some python modules needed for running lib/{filename} are missing. We will not switch to new agent"
                )
            sys.path = original_sys_path
            return False
    sys.path = original_sys_path
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
    parser.add_option(
        "-f",
        "--force",
        action="store_true",
        dest="force",
        default=False,
        help="force copy supported image files to agent without checks",
    )
    parser.add_option(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        default=False,
        help="print file actions without changing agent files",
    )
    parser.add_option(
        "--force-run",
        action="store_true",
        dest="force_run",
        default=False,
        help=SUPPRESS_HELP,
    )

    (options, args) = parser.parse_args()
    pathagent, img_agent = resolve_agent_paths()

    if options.force and not options.force_run and not options.dry_run:
        if options.verbose:
            print("\nFORCE: start detached one-shot force copy\n")
        launch_detached_force_run(verbose=options.verbose)
        sys.exit(0)

    if options.force or options.force_run:
        if options.dry_run:
            print("\nDRY-RUN FORCE: supported image files that would be copied\n")
            if not print_dry_run_copy_plan(img_agent, pathagent):
                sys.exit(120)
            sys.exit(0)
        if options.verbose:
            print("\nFORCE: copy supported image files to agent without checks\n")
        if not install_direct(img_agent, pathagent, force=True):
            sys.exit(120)
        sys.exit(1)

    # First check if machine has all necessary python modules to load image
    if options.dry_run:
        print("\nDRY-RUN: module import check skipped, no file will be changed\n")
    elif not module_needed(img_agent, verbose=(options.verbose or options.info)):
        if options.verbose or options.info:
            print("\nKO: missing python modules in image\n")
        else:
            sys.exit(122)
    elif options.verbose or options.info:
        print("\nOK: no missing python modules in image\n")

    # folder for save file supp
    rollback_pulse_xmpp_agent = os.path.abspath(
        os.path.join(
            pathagent,
            "..",
            "rollback_pulse_xmpp_agent",
        )
    )

    if not options.dry_run:
        prepare_folder_rollback(rollback_pulse_xmpp_agent, pathagent)

    objdescriptoragent = Update_Remote_Agent(pathagent, True)
    objdescriptorimage = Update_Remote_Agent(img_agent)

    descriptoragent = objdescriptoragent.get_md5_descriptor_agent()
    descriptorimage = objdescriptorimage.get_md5_descriptor_agent()
    if options.verbose or options.info or options.dry_run:
        print("--------------------------------------------")
        if descriptoragent["fingerprint"] != descriptorimage["fingerprint"]:
            print("\nThe fingerprints are different between the agent and the image")
        else:
            print("\nThe fingerprints are the same between the agent and the image")
        print("--------------------------------------------")
        if descriptoragent["version"] != descriptorimage["version"]:
            print("\nThe versions are different between the agent and the image")
        else:
            print("\nThe versions are the same between the agent and the image")
        print("--------------------------------------------")
        print(objdescriptoragent.dir_agent_base)
        print(json.dumps(descriptoragent, indent=4))
        print("--------------------------------------------")
        print(objdescriptorimage.dir_agent_base)
        print(json.dumps(descriptorimage, indent=4))
        print("--------------------------------------------")
    boolinstalldirect = True
    if descriptorimage["fingerprint"] == descriptoragent["fingerprint"]:
        if options.verbose or options.info or options.dry_run:
            print("\nNo UPDATING, no diff between agent and agentimage")
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
                if options.verbose or options.info or options.dry_run:
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
                if options.dry_run:
                    for delfile in supp2:
                        print(f"DELETE {delfile}")
                elif not options.info:
                    for delfile in supp2:
                        os.remove(delfile)
            if options.info:
                # info information sans replicator
                sys.exit(5)
            if options.dry_run:
                print("\nDRY-RUN INSTALL: supported image files that would be copied\n")
                if not print_dry_run_copy_plan(img_agent, pathagent):
                    sys.exit(120)
                sys.exit(0)
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
