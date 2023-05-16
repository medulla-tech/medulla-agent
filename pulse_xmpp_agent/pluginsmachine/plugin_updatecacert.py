# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
from lib import utils
import platform

CACERTVERSION = '1.0'

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "updatecacert", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checkcacertversion()
        if StrictVersion(installed_version) < StrictVersion(CACERTVERSION):
            updatecacert(xmppobject, installed_version)
    except Exception:
        pass


def checkcacertversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            cacertversion = result['result'][0].strip().split()[-1]
        else:
            # The certificate is not installed. We will force installation by returning
            # version 0.0
            cacertversion = '0.0'
        return cacertversion

    elif sys.platform.startswith('linux'):
        if platform.linux_distribution()[0] in ['CentOS Linux', 'centos', 'fedora', 'Red Hat Enterprise Linux Server', 'redhat', 'Mageia']:
            cacerts_path = '/etc/ssl/certs/ca-bundle.crt'
        elif platform.linux_distribution()[0] in ['debian']:
            cacerts_path = '/etc/ssl/certs/ca-certificates.crt'
        cmdCertCheck = "awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{close(cmd)};{print | cmd}' < %s |grep Pulse" % cacerts_path
        cmd_result = utils.simplecommand(cmdCertCheck)
        if cmd_result['code'] == 0:
            # The certificate is installed.
            cacertversion = CACERTVERSION
        else:
            # The certificate is not installed. We will force installation by returning
            # version 0.0
            cacertversion = '0.0'


def updatecacertversion(version):
    if sys.platform.startswith('win'):
        cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" '\
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % CACERTVERSION

        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            logger.info("We successfully updated Medulla CA Cert to version " % CACERTVERSION)

        if version == "0.0":
            cmdDisplay = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" '\
                '/v "DisplayName" /t REG_SZ  /d "Medulla CA Cert" /f'
            utils.simplecommand(cmdDisplay)

            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CA Cert" '\
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            utils.simplecommand(cmd)
            logger.info("CA Certificate version updated.")


def updatecacert(xmppobject, installed_version):
    logger.info("Updating CA Certificates.")
    filename = 'medulla-ca-chain.cert.pem'

    # Download certificate
    dl_url = 'http://%s/downloads/%s' % (
        xmppobject.config.Server, filename)
    if sys.platform.startswith('win'):
        windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)
    elif sys.platform.startswith('linux'):
        if platform.linux_distribution()[0] in ['CentOS Linux', 'centos', 'fedora', 'Red Hat Enterprise Linux Server', 'redhat', 'Mageia']:
            install_tempdir = '/etc/pki/ca-trust/source/anchors/'
        elif platform.linux_distribution()[0] in ['debian']:
            install_tempdir = '/usr/local/share/ca-certificates/'
    logger.debug("Downloading %s" % dl_url)
    result, txtmsg = utils.downloadfile(dl_url, os.path.join(install_tempdir, filename)).downloadurl()
    if result:
        # Download success
        logger.info("%s" % txtmsg)
        current_dir = os.getcwd()
        os.chdir(install_tempdir)
    else:
        # Download error
        logger.error("%s" % txtmsg)

    # Install certificate
    if sys.platform.startswith('win'):
        cmd = 'certutil -addstore root medulla-ca-chain.cert.pem'
        cmd_result = utils.simplecommand(cmd)
        if cmd_result['code'] == 0:
            logger.info("%s installed successfully to version %s" % (filename, CACERTVERSION)
            updatecacertversion(CACERTVERSION)
        else:
            logger.error("Error installing %s: %s" % (filename, cmd_result['result']))
    elif sys.platform.startswith('linux'):
        if platform.linux_distribution()[0] in ['CentOS Linux', 'centos', 'fedora', 'Red Hat Enterprise Linux Server', 'redhat', 'Mageia']:
            cmd = 'update-ca-trust extract'
        elif platform.linux_distribution()[0] in ['debian']:
            cmd = 'update-ca-certificates'
        cmd_result = utils.simplecommand(cmd)
        if cmd_result['code'] == 0:
            logger.info("%s installed successfully to version %s" % (filename, CACERTVERSION)
            updatecacertversion(CACERTVERSION)
        else:
            logger.error("Error installing %s: %s" % (filename, cmd_result['result']))
