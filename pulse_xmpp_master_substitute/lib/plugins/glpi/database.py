from lib.plugins.glpi import *

# TODO rename location into entity (and locations in location)
#from mmc.plugins.glpi.config import GlpiConfig
from lib.plugins.glpi.database_084 import  Glpi084
from lib.plugins.glpi.database_92 import Glpi92


class Glpi(DatabaseHelper):
    """
    Singleton Class to query the glpi database in version > 0.80.

    """
    is_activated = False

    def activate(self):#jid, password, room, nick):
        if self.is_activated:
            return None
        self.config = confParameter()
        self.logger = logging.getLogger()
        self.logger.debug("Glpi activation")
        self.engine = None
        self.dbpoolrecycle = 60
        self.dbpoolsize = 5
        self.sessionxmpp = None
        self.sessionglpi = None

        #utilisation glpi base
        self.engine_glpi = create_engine('mysql://%s:%s@%s:%s/%s'%( self.config.glpi_dbuser,
                                                                self.config.glpi_dbpasswd,
                                                                self.config.glpi_dbhost,
                                                                self.config.glpi_dbport,
                                                                self.config.glpi_dbname),
                                    pool_recycle = self.config.dbpoolrecycle,
                                    pool_size = self.config.dbpoolsize
        )

        try:
            self._glpi_version = self.engine_glpi.execute('SELECT version FROM glpi_configs').fetchone().values()[0].replace(' ', '')
        except OperationalError:
            self._glpi_version = self.engine_glpi.execute('SELECT value FROM glpi_configs WHERE name = "version"').fetchone().values()[0].replace(' ', '')

        if Glpi084().try_activation(self.config):
            self.database = Glpi084()
        elif Glpi92().try_activation(self.config):
            self.database = Glpi92()
        elif Glpi93().try_activation(self.config):
            self.database = Glpi93()
        elif Glpi94().try_activation(self.config):
            self.database = Glpi94()

    @property
    def glpi_version(self):
        return self._glpi_version

    def glpi_version_new(self):
        return False

    def getTableName(self, name):
        return ''.join(map(lambda x:x.capitalize(), name.split('_')))

    def __getattr__(self, attr_name):
        return getattr(self.database, attr_name)
