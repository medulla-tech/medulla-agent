# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from lib import utils

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "0.0.9", "NAME": "banmachines", "VERSIONAGENT": "2.0.0", "TYPE": "relayserver", "DESC": "Ban specified machines from the relay"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, message, dataerror):
    logger.debug("###################################################")
    logger.debug("call %s from %s session id %s" % (plugin, message["from"], sessionid))
    logger.debug("###################################################")

    if data["subaction"] == "direct_ban":
        result = []
        for machine in data["jid_machines"]:
            user, host = machine.split("/")[0].split("@")
            _result = utils.simplecommand(
                "ejabberdctl ban_account %s %s %s" % (user, host, data["subaction"])
            )
            result.append(_result)

    if data["subaction"] == "direct_unban":
        result = []
        for machine in data["jid_machines"]:
            user, host = machine.split("/")[0].split("@")
            _result = utils.simplecommand("ejabberdctl unregister %s %s" % (user, host))

            result.append(_result)
