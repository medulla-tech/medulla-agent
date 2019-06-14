#!/bin/bash

export STNODEFAULTFOLDER=1;nohup /usr/bin/syncthing -home="/etc/pulse-xmpp-agent/syncthing" -logfile="/var/log/pulse"&
