import os
from lib.utils import shellcommandtimeout

# nb  -1 infinie
# all tuesday at 22h30
SCHEDULE = {"schedule" : "30 22 * * 2", "nb" : -1}

def schedule_main(objectxmpp):
    """ install
    /usr/lib/python2.7/dist-packages/pulse_xmpp_agent/descriptorscheduler/scheduling_wsusscn2.py
    download file Wsusscn2.cab on link http://go.microsoft.com/fwlink/p/?LinkID=74689

    """
    print "*******************************************"
    print "*******************************************"
    print "*******************************************"
    try:
        os.makedirs("/var/lib/pulse2/Wsusscn2", 0700)
    except OSError:
        pass
    re = shellcommandtimeout("wget -O Wsusscn2.cab -P /var/lib/pulse2/Wsusscn2 http://go.microsoft.com/fwlink/p/?LinkID=74689", 600).run()
    print re['codereturn']
    result  = [x.strip('\n') for x in re['result'] if x !='']
    print result
    print "*******************************************"
    print "*******************************************"
    print "*******************************************"
### http://go.microsoft.com/fwlink/p/?LinkID=74689
