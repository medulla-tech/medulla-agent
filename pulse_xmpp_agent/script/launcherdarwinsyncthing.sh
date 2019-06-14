#!/bin/bash

export STNODEFAULTFOLDER=1;nohup /Library/Application\ Support/Pulse/bin/syncthing -home="/Library/Application\ Support/Pulse/etc/" -logfile="/Library/Application\ Support/Pulse/var/log/" -no-browser & >/tmp/launcher.logfile
