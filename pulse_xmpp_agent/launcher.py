#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.networkinfo import networkagentinfo
from lib.configuration import  parametreconf

import os

if __name__ == '__main__':
    tg = parametreconf()
    print tg.agenttype
    if tg.agenttype in ["relaisserver","relayserver"]:
        os.system('./connectionagent.py')
        os.system('./agentxmpp.py')
    else:
        os.system('./agentxmpp.py')
