# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from lib.agentconffile import directoryconffile
import os
import shutil
import logging
import datetime
import zipfile
import bz2
import gzip
import configparser
from lib.utils import file_put_contents

logger = logging.getLogger()
plugin = {"VERSION": "2.3", "NAME": "scheduling_logsrotation", "TYPE": "all", "SCHEDULED": True,}  # fmt: skip

# nb -1 infinie
SCHEDULE = {"schedule": "0 */2 * * *", "nb": -1}


def schedule_main(objectxmpp):
    """
    Rotates agent log file everyday at 12:00
    We keep 1 week worth of logs
    """
    date = datetime.datetime.now()
    logger.debug("=================scheduling_logsrotation=================")
    logger.debug(f"call scheduled {plugin} at {str(date)}")
    logger.debug(f"crontab {SCHEDULE}")
    logger.debug("=========================================================")
    num_compteur = getattr(objectxmpp, f'num_call_{plugin["NAME"]}')
    if num_compteur == 0:
        read_config_plugin_agent(objectxmpp)

    logger.debug(
        (
            "Parameters\n\tlog file is : %s\n"
            "\tconfiguration file is : %s\n"
            "\tnumber file in rotation is : %s\n"
            "\tcompress Mode is : %s\n"
            "\ttrigger_size is %s bytes\n"
            "\tLevel logging %s"
            % (
                objectxmpp.config.logfile,
                os.path.join(directoryconffile(), f'{plugin["NAME"]}.ini'),
                objectxmpp.nbrotfile,
                objectxmpp.compress,
                objectxmpp.trigger_size,
                logging.getLevelName(logger.getEffectiveLevel()),
            )
        )
    )

    compressionMode = objectxmpp.compress  # mode in zip, gzip, bz2, No

    if compressionMode == "no":
        compressionMode = ""
    elif compressionMode == "gzip":
        compressionMode = ".gz"
    else:
        compressionMode = f".{compressionMode}"
    if (
        os.path.isfile(objectxmpp.config.logfile)
        and os.path.getsize(objectxmpp.config.logfile) >= objectxmpp.trigger_size
    ):
        # check if we even need to rotate
        logger.debug(f"start rotation log {objectxmpp.config.logfile}")

        for i in range(objectxmpp.nbrotfile, 0, -1):  # count backwards
            logger.debug(f"i {i} ")
            if i == 0:
                old_name = f"{objectxmpp.config.logfile}"
            else:
                old_name = f"{objectxmpp.config.logfile}.{i}{compressionMode}"
            new_name = f"{objectxmpp.config.logfile}.{i + 1}{compressionMode}"
            try:
                logger.debug(f"copy file log {old_name} to {new_name}")
                shutil.copyfile(old_name, new_name)
            except BaseException:
                pass
        if objectxmpp.compress == "zip":  # utilitaire unzip
            try:
                logger.debug(
                    f"compress {objectxmpp.config.logfile} in {objectxmpp.config.logfile}.1.zip"
                )
                with zipfile.ZipFile(f"{objectxmpp.config.logfile}.1.zip", "w") as f:
                    f.write(
                        objectxmpp.config.logfile,
                        f"{objectxmpp.config.logfile}.1.zip",
                        zipfile.ZIP_DEFLATED,
                    )
                    # shutil.copyfile(objectxmpp.config.logfile, objectxmpp.config.logfile + '.1')
            except BaseException:
                pass
        elif objectxmpp.compress in ["gzip", "gz"]:  # decompress to stdout zcat
            try:
                logger.debug(
                    f"copy file log {objectxmpp.config.logfile} to {objectxmpp.config.logfile}.1.gz"
                )
                with (
                    open(objectxmpp.config.logfile, "rb") as f_in,
                    gzip.open(f"{objectxmpp.config.logfile}.1.gz", "wb") as f_out,
                ):
                    shutil.copyfileobj(f_in, f_out)
            except BaseException:
                pass
        elif objectxmpp.compress == "bz2":  # decompress to stdout bzcat
            try:
                logger.debug(
                    f"copy file log {objectxmpp.config.logfile} to {objectxmpp.config.logfile}.1.bz2"
                )
                with (
                    open(objectxmpp.config.logfile, "rb") as f_in,
                    open(f"{objectxmpp.config.logfile}.1.bz2", "wb") as f_out,
                ):
                    f_out.write(bz2.compress(f_in.read(), 9))
            except BaseException:
                pass
        elif objectxmpp.compress == "no":
            try:
                logger.debug(
                    f"copy file log {objectxmpp.config.logfile} to {objectxmpp.config.logfile}.1"
                )
                shutil.copyfile(
                    objectxmpp.config.logfile, f"{objectxmpp.config.logfile}.1"
                )
            except BaseException:
                pass
        open(objectxmpp.config.logfile, "w").close()  # Truncate the log file


def read_config_plugin_agent(objectxmpp):
    configfilename = os.path.join(directoryconffile(), f'{plugin["NAME"]}.ini')
    if not os.path.isfile(configfilename):
        logger.warning(f"there is no configuration file : {configfilename}")
        logger.warning("the missing configuration file is created automatically.")
        file_put_contents(
            configfilename,
            "# file log is : %s\n"
            "[rotation_file]\n"
            "# Number of files kept after rotation\n"
            "nb_rot_file = 6\n"
            "# Log file compression chosen in the following list: no | zip | gzip | bz2\n"
            "compress = no\n"
            "# Maximum file size in bytes. If file size > trigger_size, log is rotated\n"
            "trigger_size = 1048576\n" % objectxmpp.config.logfile,
        )
    Config = configparser.ConfigParser()
    Config.read(configfilename)
    try:
        objectxmpp.nbrotfile = Config.getint("rotation_file", "nb_rot_file")
    except BaseException:
        objectxmpp.nbrotfile = 6

    objectxmpp.nbrotfile = max(objectxmpp.nbrotfile, 1)
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
        objectxmpp.trigger_size = 1048576
