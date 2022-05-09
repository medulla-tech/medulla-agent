# -*- coding: utf-8 -*-
#
# (c) 2020 siveo, http://www.siveo.net
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
# file : plugin_updatefileviewer.py

import sys
import os
from distutils.version import StrictVersion
import logging
from lib import utils

BOOTSTRAP = "3.1.1"
JQUERY = "3.5.1"
JQUERYUI = "1.12.1"
DATATABLES = "1.10.22"
MAIN = "1.0"
list_modules = ["bootstrap", "jquery", "jqueryui", "datatables", "main"]

logger = logging.getLogger()
plugin = {"VERSION": "1.3", "NAME": "updatefileviewer", "TYPE": "machine"}  # fmt: skip


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")

    create_subdirs()

    try:
        # Update if version is lower
        main_installed_version = checkversion("main")
        if StrictVersion(main_installed_version) < StrictVersion(MAIN):
            updatemain(xmppobject)

        bootstrap_installed_version = checkversion("bootstrap")
        if StrictVersion(bootstrap_installed_version) < StrictVersion(BOOTSTRAP):
            updatebootstrap(xmppobject)

        jquery_installed_version = checkversion("jquery")
        if StrictVersion(jquery_installed_version) < StrictVersion(JQUERY):
            updatejquery(xmppobject)

        jqueryui_installed_version = checkversion("jqueryui")
        if StrictVersion(jqueryui_installed_version) < StrictVersion(JQUERYUI):
            updatejqueryui(xmppobject)

        datatable_installed_version = checkversion("datatables")
        if StrictVersion(datatable_installed_version) < StrictVersion(DATATABLES):
            updatedatatables(xmppobject)

    except Exception:
        pass


def fileviewer_path():
    if sys.platform.startswith("win"):
        destpath = os.path.join(
            "c:\\",
            "Python27",
            "Lib",
            "site-packages",
            "pulse_xmpp_agent",
            "lib",
            "ressources",
            "fileviewer",
        )
    elif sys.platform.startswith("linux"):
        rpm_python_path = os.path.join(
            "/", "usr", "lib", "python2.7", "site-packages", "pulse_xmpp_agent"
        )
        pip_python_path = os.path.join(
            "/", "usr", "local", "lib", "python2.7", "dist-packages", "pulse_xmpp_agent"
        )
        deb_python_path = os.path.join(
            "/", "usr", "lib", "python2.7", "dist-packages", "pulse_xmpp_agent"
        )
        if os.path.isdir(pip_python_path):
            destpath = os.path.join(pip_python_path, "lib", "ressources", "fileviewer")
        elif os.path.isdir(deb_python_path):
            destpath = os.path.join(deb_python_path, "lib", "ressources", "fileviewer")
        else:
            destpath = os.path.join(rpm_python_path, "lib", "ressources", "fileviewer")

    elif sys.platform.startswith("darwin"):
        print("Not implemented yet")

    return destpath


def checkbootstrapversion():
    installed_path = fileviewer_path()
    bootstrap_version_file = os.path.join(installed_path, "bootstrap.version")

    if not os.path.isdir(installed_path) or not os.path.isfile(bootstrap_version_file):
        bootstrapversion = "0.1"
    else:
        bootstrapversion = utils.file_get_contents(bootstrap_version_file).strip()

    return bootstrapversion


def get_version_file(deps_module):
    installed_path = fileviewer_path()

    if deps_module == "main":
        version_file = os.path.join(installed_path, "main.version")
    elif deps_module == "bootstrap":
        version_file = os.path.join(installed_path, "bootstrap.version")
    elif deps_module == "jquery":
        version_file = os.path.join(installed_path, "jquery.version")
    elif deps_module == "jqueryui":
        version_file = os.path.join(installed_path, "jqueryui.version")
    elif deps_module == "datatables":
        version_file = os.path.join(installed_path, "datatables.version")
    else:
        logger.error("The module %s is not supported" % deps_module)

    return version_file


def checkversion(deps_module):
    version_file = get_version_file(deps_module)
    installed_path = fileviewer_path()

    if not os.path.isdir(installed_path) or not os.path.isfile(version_file):
        module_version = "0.1"
    else:
        module_version = utils.file_get_contents(version_file).strip()

    return module_version


def write_version_in_file(deps_module, version_module):
    version_file = get_version_file(deps_module)

    with open(version_file, "w") as filout:
        filout.write(version_module)


def updatemain(xmppobject):
    installed_path = fileviewer_path()

    filename_css = "style.css"
    filename_js = "script.js"

    if sys.platform.startswith("win"):
        architecture = "win"
    elif sys.platform.startswith("linux"):
        architecture = "lin"
    elif sys.platform.startswith("darwin"):
        architecture = "mac"

    dl_url_css = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_css,
    )

    result_css, txtmsg_css = utils.downloadfile(
        dl_url_css, os.path.join(installed_path, "css", filename_css)
    ).downloadurl()
    if result_css:
        # Download success
        logger.debug("%s" % txtmsg_css)
    else:
        # Download error
        logger.debug("%s" % txtmsg_css)

    dl_url_js = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_js,
    )

    result_js, txtmsg_js = utils.downloadfile(
        dl_url_js, os.path.join(installed_path, "js", filename_js)
    ).downloadurl()
    if result_js:
        # Download success
        logger.debug("%s" % txtmsg_js)
    else:
        # Download error
        logger.error("%s" % txtmsg_js)

    write_version_in_file("main", MAIN)


def updatebootstrap(xmppobject):
    logger.info("Updating Bootstrap to version %s" % BOOTSTRAP)

    installed_path = fileviewer_path()

    filename_css = "bootstrap.css"
    filename_js = "bootstrap.js"

    if sys.platform.startswith("win"):
        architecture = "win"
    elif sys.platform.startswith("linux"):
        architecture = "lin"
    elif sys.platform.startswith("darwin"):
        architecture = "mac"

    dl_url_css = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_css,
    )

    result_css, txtmsg_css = utils.downloadfile(
        dl_url_css, os.path.join(installed_path, "css", filename_css)
    ).downloadurl()
    if result_css:
        # Download success
        logger.debug("%s" % txtmsg_css)
    else:
        # Download error
        logger.debug("%s" % txtmsg_css)

    dl_url_js = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_js,
    )

    result_js, txtmsg_js = utils.downloadfile(
        dl_url_js, os.path.join(installed_path, "js", filename_js)
    ).downloadurl()
    if result_js:
        # Download success
        logger.debug("%s" % txtmsg_js)
    else:
        # Download error
        logger.error("%s" % txtmsg_js)

    write_version_in_file("bootstrap", BOOTSTRAP)


def updatejquery(xmppobject):
    logger.info("Updating JQuery to version %s" % JQUERY)

    installed_path = fileviewer_path()

    filename_js = "jquery-%s.js" % JQUERY
    postfilename_js = "jquery.js"

    if sys.platform.startswith("win"):
        architecture = "win"
    elif sys.platform.startswith("linux"):
        architecture = "lin"
    elif sys.platform.startswith("darwin"):
        architecture = "mac"

    dl_url_js = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_js,
    )

    result_js, txtmsg_js = utils.downloadfile(
        dl_url_js, os.path.join(installed_path, "js", postfilename_js)
    ).downloadurl()
    if result_js:
        # Download success
        logger.debug("%s" % txtmsg_js)
    else:
        # Download error
        logger.error("%s" % txtmsg_js)

    write_version_in_file("jquery", JQUERY)


def updatedatatables(xmppobject):
    logger.info("Updating Datatable to version %s" % DATATABLES)

    installed_path = fileviewer_path()

    filename_css = "jquery.dataTables.css"
    postfilename_css = "datatables.css"
    filename_js = "jquery.dataTables.js"
    postfilename_js = "datatables.js"
    filename_woff = "glyphicons-halflings-regular.woff"

    if sys.platform.startswith("win"):
        architecture = "win"
    elif sys.platform.startswith("linux"):
        architecture = "lin"
    elif sys.platform.startswith("darwin"):
        architecture = "mac"

    dl_url_js = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_js,
    )

    result_js, txtmsg_js = utils.downloadfile(
        dl_url_js, os.path.join(installed_path, "js", postfilename_js)
    ).downloadurl()
    if result_js:
        # Download success
        logger.debug("%s" % txtmsg_js)
    else:
        # Download error
        logger.error("%s" % txtmsg_js)

    dl_url_css = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_css,
    )
    result_css, txtmsg_css = utils.downloadfile(
        dl_url_css, os.path.join(installed_path, "css", postfilename_css)
    ).downloadurl()
    if result_js:
        # Download success
        logger.debug("%s" % txtmsg_css)
    else:
        # Download error
        logger.error("%s" % txtmsg_css)

    dl_url_woff = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_woff,
    )
    result_woff, txtmsg_woff = utils.downloadfile(
        dl_url_woff, os.path.join(installed_path, "fonts", filename_woff)
    ).downloadurl()
    if result_woff:
        # Download success
        logger.debug("%s" % txtmsg_woff)
    else:
        # Download error
        logger.error("%s" % txtmsg_css)

    write_version_in_file("datatables", DATATABLES)


def updatejqueryui(xmppobject):
    logger.info("Updating JQuery UI to version %s" % JQUERY)

    installed_path = fileviewer_path()

    filename_js = "jquery-ui.js"
    filename_css = "jquery-ui.css"

    if sys.platform.startswith("win"):
        architecture = "win"
    elif sys.platform.startswith("linux"):
        architecture = "lin"
    elif sys.platform.startswith("darwin"):
        architecture = "mac"

    dl_url_css = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_css,
    )

    result_css, txtmsg_css = utils.downloadfile(
        dl_url_css, os.path.join(installed_path, "css", filename_css)
    ).downloadurl()
    if result_css:
        # Download success
        logger.debug("%s" % txtmsg_css)
    else:
        # Download error
        logger.error("%s" % txtmsg_css)

    dl_url_js = "http://%s/downloads/%s/downloads/%s" % (
        xmppobject.config.Server,
        architecture,
        filename_js,
    )
    result_js, txtmsg_js = utils.downloadfile(
        dl_url_js, os.path.join(installed_path, "js", filename_js)
    ).downloadurl()
    if result_js:
        # Download success
        logger.debug("%s" % txtmsg_js)
    else:
        # Download error
        logger.error("%s" % txtmsg_js)

    write_version_in_file("jqueryui", JQUERYUI)


def create_subdirs():
    installed_path = fileviewer_path()
    css_path = os.path.join(installed_path, "css")
    js_path = os.path.join(installed_path, "js")
    images_path = os.path.join(installed_path, "images")
    fonts_path = os.path.join(installed_path, "fonts")

    paths = [installed_path, css_path, js_path, images_path, fonts_path]
    for _path in paths:
        if not os.path.isdir(_path):
            os.makedirs(_path, 0o755)
