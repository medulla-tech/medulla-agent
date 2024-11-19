# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
from lib import utils
import platform
import tempfile
from lib.agentconffile import (
    medullaPath,
)

CACERTVERSION = "1.2"

logger = logging.getLogger()

plugin = {"VERSION": "1.3", "NAME": "updatecacert", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checkcacertversion()
        if StrictVersion(installed_version) < StrictVersion(CACERTVERSION):
            updatecacert(xmppobject, installed_version)
    except Exception:
        pass


def checkcacertversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            cacertversion = result["result"][0].strip().split()[-1]
        else:
            # The certificate is not installed. We will force installation by returning
            # version 0.0
            cacertversion = "0.0"
        return cacertversion

    elif sys.platform.startswith("linux"):
        if platform.linux_distribution()[0] in [
            "CentOS Linux",
            "centos",
            "fedora",
            "Red Hat Enterprise Linux Server",
            "redhat",
            "Mageia",
        ]:
            cacerts_path = "/etc/ssl/certs/ca-bundle.crt"
        elif platform.linux_distribution()[0] in ["debian"]:
            cacerts_path = "/etc/ssl/certs/ca-certificates.crt"
        cmdCertCheck = (
            "awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{close(cmd)};{print | cmd}' < %s |grep Pulse"
            % cacerts_path
        )
        cmd_result = utils.simplecommand(cmdCertCheck)
        if cmd_result["code"] == 0:
            # The certificate is installed.
            cacertversion = CACERTVERSION
        else:
            # The certificate is not installed. We will force installation by returning
            # version 0.0
            cacertversion = "0.0"


def updatecacertversion(version):
    if sys.platform.startswith("win"):
        commands = [
            f'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" '
            f'/v "DisplayVersion" /t REG_SZ  /d "{CACERTVERSION}" /f',
            f'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" '
            f'/v "DisplayIcon" /t REG_SZ /d "{os.path.join(medullaPath(), "bin", "install.ico")}" /f',
        ]

        for cmd in commands:
            result = utils.simplecommand(cmd)
            if result["code"] == 0:
                logger.info(f"We successfully updated Medulla CA Cert to version {CACERTVERSION}")
            else:
                logger.error(f"Failed to execute command: {cmd}")

        if version == "0.0":
            commands = [
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" '
                '/v "DisplayName" /t REG_SZ  /d "Medulla CA Cert" /f',
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" '
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f',
                f'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" '
                f'/v "DisplayIcon" /t REG_SZ /d "{os.path.join(medullaPath(), "bin", "install.ico")}" /f',
            ]

            for cmd in commands:
                result = utils.simplecommand(cmd)
            logger.info("CA Certificate version updated.")


def updatecacert(xmppobject, installed_version):
    logger.info("Updating CA Certificates.")
    filename_chain = "medulla-ca-chain.cert.pem"
    filename_root = "medulla-rootca.cert.pem"

    # Download certificate
    dl_url_chain = "http://%s/downloads/%s" % (xmppobject.config.Server, filename_chain)
    dl_url_root = "http://%s/downloads/%s" % (xmppobject.config.Server, filename_root)
    if sys.platform.startswith("win"):
        windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)
    elif sys.platform.startswith("linux"):
        if platform.linux_distribution()[0] in [
            "CentOS Linux",
            "centos",
            "fedora",
            "Red Hat Enterprise Linux Server",
            "redhat",
            "Mageia",
        ]:
            install_tempdir = "/etc/pki/ca-trust/source/anchors/"
        elif platform.linux_distribution()[0] in ["debian"]:
            install_tempdir = "/usr/local/share/ca-certificates/"
    logger.debug("Downloading %s" % dl_url_chain)
    result, txtmsg = utils.downloadfile(
        dl_url_chain, os.path.join(install_tempdir, filename_chain)
    ).downloadurl()
    if result:
        # Download success
        logger.info("%s" % txtmsg)
    else:
        # Download error
        logger.error("%s" % txtmsg)
    logger.debug("Downloading %s" % dl_url_root)
    result, txtmsg = utils.downloadfile(
        dl_url_root, os.path.join(install_tempdir, filename_root)
    ).downloadurl()
    if result:
        # Download success
        logger.info("%s" % txtmsg)
    else:
        # Download error
        logger.error("%s" % txtmsg)
    current_dir = os.getcwd()
    os.chdir(install_tempdir)

    # Install certificate
    if sys.platform.startswith("win"):
        cmd = "certutil -addstore root %s" % filename_root
        cmd_result = utils.simplecommand(cmd)
        if cmd_result["code"] == 0:
            logger.info(
                "%s installed successfully to version %s"
                % (filename_root, CACERTVERSION)
            )
        else:
            logger.error(
                "Error installing %s: %s" % (filename_root, cmd_result["result"])
            )
        cmd = "certutil -addstore ca %s" % filename_chain
        cmd_result = utils.simplecommand(cmd)
        if cmd_result["code"] == 0:
            logger.info(
                "%s installed successfully to version %s"
                % (filename_chain, CACERTVERSION)
            )
            updatecacertversion(CACERTVERSION)
        else:
            logger.error(
                "Error installing %s: %s" % (filename_chain, cmd_result["result"])
            )
    elif sys.platform.startswith("linux"):
        if platform.linux_distribution()[0] in [
            "CentOS Linux",
            "centos",
            "fedora",
            "Red Hat Enterprise Linux Server",
            "redhat",
            "Mageia",
        ]:
            cmd = "update-ca-trust extract"
        elif platform.linux_distribution()[0] in ["debian"]:
            cmd = "update-ca-certificates"
        cmd_result = utils.simplecommand(cmd)
        if cmd_result["code"] == 0:
            logger.info(
                "%s installed successfully to version %s"
                % (filename_chain, CACERTVERSION)
            )
            updatecacertversion(CACERTVERSION)
        else:
            logger.error(
                "Error installing %s: %s" % (filename_chain, cmd_result["result"])
            )
