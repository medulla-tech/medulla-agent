# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
    This plugin is created to help rotating logs
"""
import os
import shutil
import logging
import datetime
import zipfile
import bz2
import gzip
import configparser
from lib.utils import file_put_contents
import traceback

logger = logging.getLogger()
plugin = { "VERSION": "1.0", "NAME": "scheduling_sub_logsrotation", "TYPE": "all", "SCHEDULED": True, }  # fmt: skip

# nb -1 means infinite
# everyday at 12:00
# SCHEDULE = {"schedule" : "0 */2 * * *", "nb" : -1}

SCHEDULE = {"schedule": "* */1 * * *", "nb": -1}


def schedule_main(objectxmpp):
    """
    Rotates agent log file everyday at 12:00
    We keep 1 week worth of logs
    """
    try:
        date = datetime.datetime.now()
        logger.debug("=================scheduling_sub_logsrotation=================")
        logger.debug("call scheduled %s at %s" % (plugin, str(date)))
        logger.debug("crontab %s" % (SCHEDULE))
        logger.debug("=========================================================")
        num_compteur = getattr(objectxmpp, "num_call_%s" % plugin["NAME"])
        logger.debug("num_compteur %s" % num_compteur)
        if num_compteur == 0:
            read_config_plugin_agent(objectxmpp)

        sizelogfile = 0
        if os.path.isfile(objectxmpp.config.logfile):
            sizelogfile = os.path.getsize(objectxmpp.config.logfile)
        else:
            logger.warning("The log file %s is missing" % objectxmpp.config.logfile)

        if num_compteur == 0:
            logger.debug(
                "\nParameters\n\tlog file is : %s (%s bytes %s kbytes - %s Mbytes)\n"
                "\tconfiguration file is : %s\n"
                "\tnumber file in rotation is : %s\n"
                "\tcompress Mode is : %s\n"
                "\ttrigger_size is %s bytes (%s Kbytes %s Mbytes)\n"
                "\tLevel logging %s"
                % (
                    objectxmpp.config.logfile,
                    sizelogfile,
                    sizelogfile / 1024,
                    sizelogfile / (1024 * 1024),
                    objectxmpp.pathfileconf,
                    objectxmpp.nbrotfile,
                    objectxmpp.compress,
                    objectxmpp.trigger_size,
                    objectxmpp.trigger_size / 1024,
                    objectxmpp.trigger_size / (1024 * 1024),
                    logging.getLevelName(logger.getEffectiveLevel()),
                )
            )

        compression_mode = objectxmpp.compress  # mode in zip, gzip, bz2, No

        if compression_mode == "no":
            compression_mode = ""
        elif compression_mode == "gzip":
            compression_mode = ".gz"
        else:
            compression_mode = "." + compression_mode

        if os.path.isfile(objectxmpp.config.logfile):
            if sizelogfile >= objectxmpp.trigger_size:
                # check if we even need to rotate
                logger.debug("start rotation log %s" % objectxmpp.config.logfile)

                for i in range(objectxmpp.nbrotfile, 0, -1):  # count backwards
                    logger.debug("i %s " % (i))
                    if i == 0:
                        old_name = "%s" % (objectxmpp.config.logfile)
                    else:
                        old_name = "%s.%s%s" % (
                            objectxmpp.config.logfile,
                            i,
                            compression_mode,
                        )
                    new_name = "%s.%s%s" % (
                        objectxmpp.config.logfile,
                        i + 1,
                        compression_mode,
                    )
                    try:
                        logger.debug("copy file log %s to %s" % (old_name, new_name))
                        shutil.copyfile(old_name, new_name)
                    except BaseException:
                        pass
                if objectxmpp.compress == "zip":  # utilitaire unzip
                    try:
                        logger.debug(
                            "compress %s in %s"
                            % (
                                objectxmpp.config.logfile,
                                objectxmpp.config.logfile + ".1.zip",
                            )
                        )
                        with zipfile.ZipFile(
                            objectxmpp.config.logfile + ".1.zip", "w"
                        ) as f:
                            f.write(
                                objectxmpp.config.logfile,
                                objectxmpp.config.logfile + ".1.zip",
                                zipfile.ZIP_DEFLATED,
                            )
                        # shutil.copyfile(objectxmpp.config.logfile, objectxmpp.config.logfile + '.1')
                    except BaseException:
                        pass
                # decompress to stdout zcat
                elif objectxmpp.compress in ["gzip", "gz"]:
                    try:
                        logger.debug(
                            "copy file log %s to %s"
                            % (
                                objectxmpp.config.logfile,
                                objectxmpp.config.logfile + ".1.gz",
                            )
                        )
                        with open(objectxmpp.config.logfile, "rb") as f_in, gzip.open(
                            objectxmpp.config.logfile + ".1.gz", "wb"
                        ) as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    except BaseException:
                        pass
                elif objectxmpp.compress == "bz2":  # decompress to stdout bzcat
                    try:
                        logger.debug(
                            "copy file log %s to %s"
                            % (
                                objectxmpp.config.logfile,
                                objectxmpp.config.logfile + ".1.bz2",
                            )
                        )
                        with open(objectxmpp.config.logfile, "rb") as f_in, open(
                            objectxmpp.config.logfile + ".1.bz2", "wb"
                        ) as f_out:
                            f_out.write(bz2.compress(f_in.read(), 9))
                    except BaseException:
                        pass
                elif objectxmpp.compress == "no":
                    try:
                        logger.debug(
                            "copy file log %s to %s"
                            % (
                                objectxmpp.config.logfile,
                                objectxmpp.config.logfile + ".1",
                            )
                        )
                        shutil.copyfile(
                            objectxmpp.config.logfile, objectxmpp.config.logfile + ".1"
                        )
                    except BaseException:
                        pass
                open(objectxmpp.config.logfile, "w").close()  # Truncate the log file

    except Exception as e:
        logger.error(" %s : %s" % (plugin["NAME"], str(e)))
        logger.error("\n%s" % (traceback.format_exc()))


def read_config_plugin_agent(objectxmpp):
    namefichierconf = plugin["NAME"] + ".ini"
    objectxmpp.pathfileconf = os.path.join(
        objectxmpp.config.pathdirconffile, namefichierconf
    )
    if not os.path.isfile(objectxmpp.pathfileconf):
        logger.warning("there is no configuration file : %s" % objectxmpp.pathfileconf)
        logger.warning(
            "the missing configuration file is created automatically. with trigger size 5 Mb"
        )
        file_put_contents(
            objectxmpp.pathfileconf,
            "# file log is : %s\n"
            "[rotation_file]\n"
            "# Number of files kept after rotation\n"
            "nb_rot_file = 6\n"
            "# Log file compression chosen in the following list: no | zip | gzip | bz2\n"
            "compress = no\n"
            "# Maximum file size in bytes. If file size > trigger_size, log is rotated\n"
            "trigger_size = 5242880\n" % objectxmpp.config.logfile,
        )
    Config = configparser.ConfigParser()
    Config.read(objectxmpp.pathfileconf)
    try:
        objectxmpp.nbrotfile = Config.getint("rotation_file", "nb_rot_file")
    except BaseException:
        objectxmpp.nbrotfile = 6

    if objectxmpp.nbrotfile < 1:
        objectxmpp.nbrotfile = 1

    try:
        objectxmpp.compress = Config.get("rotation_file", "compress")
    except BaseException:
        objectxmpp.compress = "no"

    objectxmpp.compress = objectxmpp.compress.lower()
    if objectxmpp.compress not in ["zip", "gzip", "bz2", "no"]:
        objectxmpp.compress = "no"
    try:
        objectxmpp.trigger_size = Config.getint("rotation_file", "trigger_size")
    except BaseException:
        objectxmpp.trigger_size = 5242880
