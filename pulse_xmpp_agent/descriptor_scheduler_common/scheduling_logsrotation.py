# file : descriptor_scheduler_machine/scheduling_logsrotation.py
from lib.agentconffile import directoryconffile
import os
import shutil
import logging
import datetime
import zipfile
import bz2
import gzip

logger = logging.getLogger()

plugin = {"VERSION": "2.1", "NAME": "scheduling_logsrotation", "TYPE": "all", "SCHEDULED": True}

# nb -1 infinie
# everyday at 12:00
SCHEDULE = {"schedule" : "00 12 * * *", "nb" : -1}

def schedule_main(objectxmpp):
    """
    Rotates agent log file everyday at 12:00
    We keep 1 week worth of logs
    """
    date = datetime.datetime.now()
    logger.debug("=================scheduling_logsrotation=================")
    logger.debug("call scheduled %s at %s"%(plugin, str(date)))
    logger.debug("crontab %s"%(SCHEDULE))
    logger.debug("=====================================================")
    logger.debug("log file agent is %s.ini" % objectxmpp.config.logfile)
    logfile = objectxmpp.config.logfile
    nbrotfile = objectxmpp.config.nbrotfile
    compress = objectxmpp.config.compress
    num_compteur = getattr(objectxmpp, "num_call_%s" % plugin['NAME'])
    if num_compteur == 0:
        read_config_plugin_agent(objectxmpp)
    type=compress # type in zip, gzip, bz2, No
    if os.path.isfile(logfile): # check if we even need to rotate
        for i in range(nbrotfile, 0, -1): # count backwards
            old_name = "%s.%s.%s" % (logfile, i, type )
            new_name = "%s.%s.%s" % (logfile, i + 1, type)
            try:
                shutil.copyfile(old_name, new_name)
            except:
                pass
        if type == "zip": # utilitaire unzip
            try:
                with zipfile.ZipFile(logfile + '.1.zip', 'w') as f:
                    f.write(logfile, logfile + '.1.zip', zipfile.ZIP_DEFLATED)
                #shutil.copyfile(logfile, logfile + '.1')
            except:
                pass
        elif type == "gzip": # decompress to stdout zcat
            try:
                with open(logfile, 'rb') as f_in:
                    with gzip.open(logfile + '.1.gz', 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            except:
                pass
        elif type == "bz2": # decompress to stdout bzcat
            try:
                with open(logfile, 'rb') as f_in:
                    with open(logfile + '.1.bz2', 'wb') as f_out:
                        f_out.write(bz2.compress(f_in.read(), 9))
            except:
                pass
        elif type == "no":
            try:
                shutil.copyfile(logfile, logfile + '.1')
            except:
                pass
        open(logfile, 'w').close() # Truncate the log file

def read_config_plugin_agent(objectxmpp):
    configfilename = os.path.join(directoryconffile(), plugin['NAME'])
    logger.info("Plugin %s configuration file is %s" % (plugin['NAME'],
                                                        configfilename))
    if os.path.isfile(configfilename):
        # lit la configuration
        # Config = ConfigParser.ConfigParser()
        # Config.read(configfilename)
        logger.warning(" implementation config file missing for plugin %s" % plugin['NAME'])
        pass
    else:
        logger.info("configuration file missing for plugin %s " % plugin['NAME'])

