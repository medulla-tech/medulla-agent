# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
from lib import utils

BOOTSTRAP = "5.2.3"
JQUERY = "3.6.4"
JQUERYUI = "1.13.1"
DATATABLES = "1.13.4"
MAIN = "1.1"
list_modules = ["bootstrap", "jquery", "jqueryui", "datatables", "main"]

logger = logging.getLogger()
plugin = {"VERSION": "1.6", "NAME": "updatefileviewer", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
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
    version_info = utils.PythonVersionInfo()
    if sys.platform.startswith("win"):
        destpath = os.path.join(
            version_info.path_lib,
            "site-packages",
            "pulse_xmpp_agent",
            "lib",
            "ressources",
            "fileviewer",
        )
    elif sys.platform.startswith("linux"):
        rpm_python_path = os.path.join(
            "/", "usr", "lib", "python3", "site-packages", "pulse_xmpp_agent"
        )
        pip_python_path = os.path.join(
            "/", "usr", "local", "lib", "python3", "dist-packages", "pulse_xmpp_agent"
        )
        deb_python_path = os.path.join(
            "/", "usr", "lib", "python3", "dist-packages", "pulse_xmpp_agent"
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
