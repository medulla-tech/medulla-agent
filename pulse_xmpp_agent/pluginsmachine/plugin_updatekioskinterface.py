# SPDX-FileCopyrightText: 2020-2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import glob
import importlib.util
from distutils.version import StrictVersion
import logging
import psutil
from lib import utils
import shutil
import signal
import tarfile
import tempfile
import time
from lib.agentconffile import (
    medullaPath,
)

KIOSKINTERFACEVERSION = "2.1.5"

logger = logging.getLogger()

plugin = {"VERSION": "1.15", "NAME": "updatekioskinterface", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):

    if not sys.platform.startswith(("win", "linux", "darwin")):
        return
    logger.debug("PL-KIOSK ###################################################")
    logger.debug("PL-KIOSK call %s from %s" % (plugin, message["from"]))
    logger.debug("PL-KIOSK ###################################################")
    try:
        # Update if version is lower
        installed_version = kioskinterfaceversion()
        if StrictVersion(installed_version) < StrictVersion(KIOSKINTERFACEVERSION):
            updatekioskinterface(xmppobject, installed_version)
        elif sys.platform.startswith(("linux", "darwin")):
            restart_outdated_kiosk(xmppobject)
    except Exception:
        pass


def kioskinterfaceversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            KIOSKINTERFACEVERSION = result["result"][0].strip().split()[-1]
        else:
            # Not installed. We will force installation by returning
            # version 0.1
            KIOSKINTERFACEVERSION = "0.1"

        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" /v "DisplayIcon"'
        result = utils.simplecommand(cmd)

        if result["code"] != 0:
            cmd = (
                f'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" '
                f'/v "DisplayIcon" /t REG_SZ /d "{os.path.join(medullaPath(), "bin", "install.ico")}" /f'
            )
            utils.simplecommand(cmd)
    elif sys.platform.startswith(("linux", "darwin")):
        # On Linux and macOS the kiosk is a pip package inside the Medulla venv. Ask pip
        # for the installed version; if it is not installed, return a low
        # version so the comparison in action() forces an install.
        cmd = "%s -m pip show kiosk_interface" % sys.executable
        result = utils.simplecommand(cmd)
        installed = "0.1"
        if result["code"] == 0:
            for line in result["result"]:
                if line.lower().startswith("version:"):
                    installed = line.split(":", 1)[1].strip()
                    break
        return installed
    return KIOSKINTERFACEVERSION


def updatekioskinterfaceversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % KIOSKINTERFACEVERSION
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info(
                "PL-KIOSK we successfully updated Medulla kiosk interface to version %s"
                % KIOSKINTERFACEVERSION
            )

        if version == "0.1":
            cmdDisplay = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" '
                '/v "DisplayName" /t REG_SZ  /d "Medulla kiosk interface" /f'
            )
            utils.simplecommand(cmdDisplay)

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" '
                '/v "Publisher" /t REG_SZ  /d "Medulla" /f'
            )

            utils.simplecommand(cmd)


def updatekioskinterface(xmppobject, installed_version):
    logger.info(
        "PL-KIOSK Updating Medulla kiosk interface to version %s"
        % KIOSKINTERFACEVERSION
    )
    version_info = utils.PythonVersionInfo()
    if sys.platform.startswith("win"):
        windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

        filename = "kiosk-interface-%s.tar.gz" % KIOSKINTERFACEVERSION
        dl_url = "%s/downloads/%s" % (xmppobject.config.update_server, filename)
        logger.debug("PL-KIOSK Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(install_tempdir, filename)
        ).downloadurl()
        if result:
            logger.debug("PL-KIOSK %s" % txtmsg)
            cmd = (
                'C:\\Progra~1\\Python%s\\Scripts\\pip%s install --quiet --upgrade --no-index --find-links="%s" %s'
                % (
                    version_info.version_major,
                    version_info.version_major,
                    install_tempdir,
                    filename,
                )
            )
            os.chdir(install_tempdir)
            logger.debug("PL-KIOSK Running %s" % cmd)
            cmd_result = utils.simplecommand(cmd)
            if cmd_result["code"] == 0:
                logger.info(
                    "PL-KIOSK %s installed successfully to version %s"
                    % (filename, KIOSKINTERFACEVERSION)
                )
                updatekioskinterfaceversion(installed_version)
                # Kill the running kiosk so the new code loads (pip only upgrades
                # the files; without this the update needs a reboot).
                # scheduling_launch_kiosk relaunches it. Mirrors the Linux branch.
                try:
                    with open(
                        "C:\\Program Files\\Medulla\\bin\\kiosk.pid"
                    ) as pidfile:
                        kpid = int(pidfile.read().strip())
                    utils.simplecommand("taskkill /PID %s /F" % kpid)
                    logger.info(
                        "PL-KIOSK killed running kiosk (pid %s) so the new "
                        "version is reloaded" % kpid
                    )
                except Exception:
                    pass
            else:
                logger.error(
                    "PL-KIOSK Error installing %s: %s"
                    % (filename, cmd_result["result"])
                )

        else:
            # Download error
            logger.error("PL-KIOSK %s" % txtmsg)
    elif sys.platform.startswith(("linux", "darwin")):
        # Same flow as Windows, but using the Medulla venv's pip (sys.executable).
        install_tempdir = tempfile.mkdtemp()

        filename = "kiosk-interface-%s.tar.gz" % KIOSKINTERFACEVERSION
        dl_url = "%s/downloads/%s" % (xmppobject.config.update_server, filename)
        logger.debug("PL-KIOSK Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(install_tempdir, filename)
        ).downloadurl()
        if result:
            logger.debug("PL-KIOSK %s" % txtmsg)
            # macOS ships a recent pip that always builds in an isolated
            # environment and fetches setuptools for it, which cannot work
            # offline (--no-index). Build with the setuptools of the venv.
            build_options = (
                " --no-build-isolation" if sys.platform.startswith("darwin") else ""
            )
            cmd = (
                '%s -m pip install --quiet --upgrade --no-index%s --find-links="%s" %s'
                % (sys.executable, build_options, install_tempdir, filename)
            )
            os.chdir(install_tempdir)
            logger.debug("PL-KIOSK Running %s" % cmd)
            cmd_result = utils.simplecommand(cmd)
            if cmd_result["code"] == 0:
                logger.info(
                    "PL-KIOSK %s installed successfully to version %s"
                    % (filename, KIOSKINTERFACEVERSION)
                )
                if sys.platform.startswith("darwin"):
                    refresh_macos_kiosk_bundle(os.path.join(install_tempdir, filename))
                # Restart the running kiosk so the new code is loaded. The
                # scheduling_launch_kiosk descriptor relaunches it in the user's
                # graphical session on its next run.
                stop_kiosk(kiosk_pid(xmppobject))
            else:
                logger.error(
                    "PL-KIOSK Error installing %s: %s"
                    % (filename, cmd_result["result"])
                )
        else:
            # Download error
            logger.error("PL-KIOSK %s" % txtmsg)


MACOS_KIOSK_BUNDLE = "/Applications/Medulla Kiosk.app"


def refresh_macos_kiosk_bundle(tarball):
    """
    Update the launcher of "Medulla Kiosk.app" from the kiosk tarball.

    pip only upgrades the Python package. The bundle in /Applications holds
    its own copy of the launcher script (macos/medulla-kiosk in the tarball),
    put there by the agent installer. Changing a file of the bundle breaks its
    ad-hoc signature and macOS then refuses to open the application, so the
    bundle is signed again afterwards.
    """
    if not os.path.isdir(MACOS_KIOSK_BUNDLE):
        logger.debug("PL-KIOSK %s is not installed. Nothing to refresh" % MACOS_KIOSK_BUNDLE)
        return
    launcher = os.path.join(MACOS_KIOSK_BUNDLE, "Contents", "MacOS", "medulla-kiosk")
    try:
        with tarfile.open(tarball) as archive:
            member = next(
                (
                    m
                    for m in archive.getmembers()
                    if m.isfile() and m.name.endswith("macos/medulla-kiosk")
                ),
                None,
            )
            if member is None:
                logger.warning("PL-KIOSK No macOS launcher found in %s" % tarball)
                return
            with archive.extractfile(member) as source, open(launcher, "wb") as target:
                shutil.copyfileobj(source, target)
        os.chmod(launcher, 0o755)
        result = utils.simplecommand(
            'codesign --force --deep -s - "%s"' % MACOS_KIOSK_BUNDLE
        )
        if result["code"] == 0:
            logger.info("PL-KIOSK %s launcher updated and signed" % MACOS_KIOSK_BUNDLE)
        else:
            logger.error(
                "PL-KIOSK Error signing %s: %s" % (MACOS_KIOSK_BUNDLE, result["result"])
            )
    except Exception as e:
        logger.error("PL-KIOSK Error refreshing %s: %s" % (MACOS_KIOSK_BUNDLE, e))


def kiosk_pid(xmppobject):
    """
    Return the pid of the running kiosk on Linux and macOS, or None.

    The kiosk is the process listening on the kiosk local port. /tmp/kiosk.pid
    is only used as a fallback: it can be missing or hold the pid of a dead
    process (file cleaned from /tmp, kiosk started twice...).
    """
    port = getattr(xmppobject.config, "kiosk_local_port", 8766)
    try:
        for connection in psutil.net_connections(kind="tcp"):
            if (
                connection.status == psutil.CONN_LISTEN
                and connection.laddr
                and connection.laddr.port == port
                and connection.pid
            ):
                return connection.pid
    except Exception as e:
        logger.debug("PL-KIOSK Cannot list the listening processes: %s" % e)
    try:
        result = utils.simplecommand("lsof -nP -iTCP:%s -sTCP:LISTEN -t" % port)
        if result["code"] == 0 and result["result"]:
            return int(result["result"][0].strip())
    except Exception as e:
        logger.debug("PL-KIOSK Cannot find the kiosk with lsof: %s" % e)
    try:
        with open("/tmp/kiosk.pid") as pidfile:
            kpid = int(pidfile.read().strip())
        if psutil.pid_exists(kpid):
            return kpid
    except Exception:
        pass
    return None


def stop_kiosk(kpid):
    """
    Stop the running kiosk so that scheduling_launch_kiosk starts the installed
    version again in the user graphical session.

    Kiosk versions up to 2.1.4 can stay alive after SIGTERM (interface stopped,
    process still holding its port), and would then never be relaunched. Give
    it a few seconds, then force it.
    """
    if not kpid:
        logger.debug("PL-KIOSK No running kiosk to stop")
        return
    try:
        os.kill(kpid, signal.SIGTERM)
        for _ in range(10):
            time.sleep(0.5)
            if not psutil.pid_exists(kpid):
                logger.info("PL-KIOSK kiosk (pid %s) stopped" % kpid)
                return
        os.kill(kpid, signal.SIGKILL)
        logger.info("PL-KIOSK kiosk (pid %s) did not stop on SIGTERM, killed" % kpid)
    except ProcessLookupError:
        pass
    except Exception as e:
        logger.error("PL-KIOSK Error stopping the kiosk (pid %s): %s" % (kpid, e))


def restart_outdated_kiosk(xmppobject):
    """
    Stop a kiosk that was started before the installed version was installed.

    It still runs the previous code (an update could not stop it, for example
    because its pid file was missing). Once stopped, scheduling_launch_kiosk
    starts the installed version.
    """
    try:
        spec = importlib.util.find_spec("kiosk_interface")
        if spec is None or not spec.origin:
            return
        sitedir = os.path.dirname(os.path.dirname(spec.origin))
        metadata = glob.glob(
            os.path.join(sitedir, "kiosk_interface-*.dist-info")
        ) + glob.glob(os.path.join(sitedir, "kiosk_interface-*.egg-info"))
        if not metadata:
            return
        installed_at = max(os.path.getmtime(path) for path in metadata)
        kpid = kiosk_pid(xmppobject)
        if kpid and psutil.Process(kpid).create_time() < installed_at:
            logger.info(
                "PL-KIOSK kiosk (pid %s) was started before the installed version. "
                "Stopping it so that the installed version is started" % kpid
            )
            stop_kiosk(kpid)
    except Exception as e:
        logger.error("PL-KIOSK Error checking the running kiosk: %s" % e)
