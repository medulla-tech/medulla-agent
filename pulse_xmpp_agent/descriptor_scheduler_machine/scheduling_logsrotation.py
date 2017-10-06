from lib.configuration import confParameter
import os
import shutil

# nb -1 infinie
# everyday at 12:00
SCHEDULE = {"schedule" : "00 12 * * *", "nb" : -1}

def schedule_main(objectxmpp):
    """
    Rotates agent log file everyday at 12:00
    We keep 1 week worth of logs
    """
    print "*******************************************"
    print "Logs rotation"
    print "*******************************************"
    logfile = confParameter().logfile
    if os.path.isfile(logfile): # check if we even need to rotate
        for i in range(5, 0, -1): # count backwards
            old_name = "%s.%s" % (logfile, i)
            new_name = "%s.%s" % (logfile, i + 1)
            try:
                shutil.copyfile(old_name, new_name)
            except:
                pass
        try:
            shutil.copyfile(logfile, logfile + '.1')
        except:
            pass
        open(logfile, 'w').close() # Truncate the log file
    print "*******************************************"
