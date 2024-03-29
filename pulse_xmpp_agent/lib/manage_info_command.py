#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import threading
from .utils import getRandomName
import logging

logger = logging.getLogger()


class manage_infoconsole:
    def __init__(self, queue_in, queue_out, objectxmpp):
        self.namethread = getRandomName(5, "threadevent")
        self.objectxmpp = objectxmpp
        self.queueinfo = queue_in
        self.queueinfoout = queue_out
        self.threadevent = threading.Thread(
            name=self.namethread, target=self.loopinfoconsol
        )
        self.threadevent.start()
        logging.debug("manage event start")

    def loopinfoconsol(self):
        logging.debug("loopinfoconsol")
        while True:
            try:
                event = self.queueinfo.get(60)
                if event == "quit":
                    break
                self.objectxmpp.gestioneventconsole(event, self.queueinfoout)
            except Exception as e:
                logging.error(f"error in manage infoconsole {str(e)}")
        logging.error("quit infocommand")
