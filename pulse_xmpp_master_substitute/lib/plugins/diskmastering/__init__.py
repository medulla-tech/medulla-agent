# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2018-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Mastering database handler
"""
# SqlAlchemy
from sqlalchemy import create_engine, func, and_, or_, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import DBAPIError
import json
import base64
import zlib
import re
import os
# PULSE2 modules
# from mmc.database.database_helper import DatabaseHelper
# from mmc.plugins.pkgs import get_xmpp_package, xmpp_packages_list, package_exists
# from lib.plugins.imaging.schema import (
#     Profiles,
#     Packages,
#     Profile_has_package,
#     Profile_has_ou,
#     Acknowledgements,
# )

# Imported last
import logging
import time
from lib.configuration import confParameter
import functools
from datetime import datetime

from sqlalchemy.orm import scoped_session
from sqlalchemy.ext.automap import automap_base

Session = sessionmaker()


logger = logging.getLogger()


class Singleton(object):
    def __new__(type, *args):
        if "_the_instance" not in type.__dict__:
            type._the_instance = object.__new__(type)

        return type._the_instance


class DatabaseHelper(Singleton):
    # Session decorator to create and close session automatically
    @classmethod
    def _sessionmastering(self, func):
        @functools.wraps(func)
        def __session(self, *args, **kw):
            created = False
            if not self.sessionmastering:
                self.sessionmastering = sessionmaker(bind=self.engine_mastering_base, expire_on_commit=False)
                created = True
            result = func(self, self.session, *args, **kw)
            if created:
                self.sessionmastering.close()
                self.sessionmastering = None
            return result

        return __session

    # Session decorator to create and close session automatically
    @classmethod
    def _sessionm(self, func):
        @functools.wraps(func)
        def __sessionm(self, *args, **kw):
            session_factory = sessionmaker(bind=self.engine_mastering_base, expire_on_commit=False)
            sessionmultithread = scoped_session(session_factory)
            result = func(self, sessionmultithread, *args, **kw)
            sessionmultithread.remove()
            return result

        return __sessionm


class DiskMasteringDatabase(DatabaseHelper):
    """
    Singleton Class to query the mastering database.

    """
    is_activated = False

    def activate(self):  # jid, password, room, nick):
        if self.is_activated:
            return None
        self.logger = logging.getLogger()
        self.logger.debug("mastering activation")
        self.engine = None
        self.sessionxmpp = None
        self.sessionglpi = None
        self.sessionmastering = None
        self.config = confParameter()
        self.logger.info(
            "mastering parameters connections is "
            " user = %s,host = %s, port = %s, schema = %s,"
            " poolrecycle = %s, poolsize = %s, pooltimeout %s"
            % (
                self.config.diskmastering_dbuser,
                self.config.diskmastering_dbhost,
                self.config.diskmastering_dbport,
                self.config.diskmastering_dbname,
                self.config.diskmastering_dbpoolrecycle,
                self.config.diskmastering_dbpoolsize,
                self.config.diskmastering_dbpooltimeout,
            )
        )

        try:
            self.engine_mastering_base = create_engine(
                "mysql+pymysql://%s:%s@%s:%s/%s?charset=%s"
                % (
                    self.config.diskmastering_dbuser,
                    self.config.diskmastering_dbpasswd,
                    self.config.diskmastering_dbhost,
                    self.config.diskmastering_dbport,
                    self.config.diskmastering_dbname,
                    self.config.charset,
                ),
                pool_recycle=self.config.diskmastering_dbpoolrecycle,
                pool_size=self.config.diskmastering_dbpoolsize,
                pool_timeout=self.config.diskmastering_dbpooltimeout,
            )
            self.sessionmastering = sessionmaker(bind=self.engine_mastering_base)

            Base = automap_base()
            Base.prepare(self.engine_mastering_base, reflect=True)

            # Only federated tables (beginning by local_) are automatically mapped
            # If needed, excludes tables from this list
            exclude_table = []
            # Dynamically add attributes to the object for each mapped class
            for table_name, mapped_class in Base.classes.items():
                if table_name in exclude_table:
                    continue
                if table_name.startswith("local"):
                    setattr(self, table_name.capitalize(), mapped_class)

            self.is_activated = True
            self.logger.debug("mastering finish activation")
            return True
        except Exception as e:
            self.logger.error("We failed to connect to the mastering database.")
            self.logger.error("Please verify your configuration")
            self.is_activated = False
            return False

    def initMappers(self):
        """
        Initialize all SQLalchemy mappers needed for the mastering database
        """
        # No mapping is needed, all is done on schema file
        return

    def getDbConnection(self):
        NB_DB_CONN_TRY = 2
        ret = None
        for i in range(NB_DB_CONN_TRY):
            try:
                ret = self.db.connect()
            except DBAPIError as e:
                logging.getLogger().error(e)
            except Exception as e:
                logging.getLogger().error(e)
            if ret:
                break
        if not ret:
            raise Exception("Database mastering connection error")
        return ret


    @DatabaseHelper._sessionm
    def get_action_details(self, session, action_id, uuid):
        # Safely select action based on status, and expiration date. We can only allow to get non consumed action, non expired action.
        sql = """SELECT
    *
from actions where id = :action_id
"""
        binds = {"action_id": action_id}
        try:
            query = session.execute(text(sql), binds).all()
        except Exception as e:
            logger.error(e)
            return {}

        if query == None:
            return {}

        result = {}
        for e in query:
            result["id"] = e.id
            result["entity_id"] = e.entity_id
            result["server_id"] = e.server_id
            result["gid"] = e.gid
            result["uuid"] = e.uuid
            result["target"] = e.target
            result["name"] = e.name
            result["config"] = e.config
            result["content"] = e.content
            result["status"] = e.status
            result["date_creation"] = e.date_creation
            result["date_start"] = e.date_start
            result["date_end"] = e.date_end

        return result

    @DatabaseHelper._sessionm
    def push_log(self, session, session_id, action_id, uuid, log="", date=None):
        if date is None:
            sql = """INSERT INTO results (action_id, session_id, uuid, content) VALUES(:action_id, :session_id, :uuid, :content)"""
            bindings = {"action_id": action_id, "session_id": session_id, "uuid": uuid, "content": log}
        else:
            sql = """INSERT INTO results (action_id, session_id, uuid, content, creation_date) VALUES(:action_id, :session_id, :uuid, :content, :creation_date)"""
            bindings = {
                "action_id": action_id,
                "uuid": uuid,
                "content": log,
                "creation_date": date,
                "session_id": session_id,
            }
        try:
            session.execute(text(sql), bindings)
            session.commit()
            session.flush()
        except Exception as e:
            logging.getLogger().error(e)
        return

    @DatabaseHelper._sessionm
    def create_master(self, session, sessionid,  uuid, action_id, master_uuid, master_path="", master_size=0):

        # Get action details to retrive configuration for this master
        sql = """SELECT
            actions.entity_id,
            actions.server_id,
            actions.config,
            servers.jid,
            servers.entity_id
         from actions join servers on servers.id = actions.server_id where actions.id =:action_id"""
        binds = {"action_id": action_id}
        query = session.execute(text(sql), binds).all()
        if query == None:
            return

        entity_id = -1
        server_id = 0
        action_config = {}
        jid = ""
        server_entity_id = 0
        for e in query:
            entity_id = e[0] if e[0] != -1 else e[4]
            server_id = e[1] if e[1] is not None else 0
            try:
                action_config = json.loads(e[2]) if e[2] is not None else {}
            except Exception as e:
                logger.error(e)
                action_config = {}
            jid = e[3] if e[3] is not None else ""

        master_name = ""
        master_description = ""
        if "name" in action_config["mastering"]:
            master_name = action_config["mastering"]["name"]
        if "description" in action_config["mastering"]:
            master_description = action_config["mastering"]["description"]

        # Insert new master in database
        sql = """INSERT INTO masters (name, description, uuid, path, size) VALUES(:name, :description, :uuid, :path, :size)"""
        binds = {"name": master_name, "description": master_description, "uuid": master_uuid, "path": master_path, "size": master_size}
        try:
            session.execute(text(sql), binds)
            session.commit()
            session.flush()
        except Exception as e:
            session.rollback()
            logging.getLogger().error(e)
            return

        # Get this new master id
        master_id = 0
        sql = """SELECT id from masters where uuid = :uuid"""
        binds = {"uuid": master_uuid}
        query = session.execute(text(sql), binds).all()
        if query == None:
             return
        for e in query:
            master_id = e[0]

        # Associate this master to the entity found
        sql = """INSERT INTO mastersEntities (master_id, entity_id) VALUES(:master_id, :entity_id)"""
        binds = {"master_id": master_id, "entity_id": entity_id}

        try:
            session.execute(text(sql), binds)

        except Exception as e:
            session.rollback()
            logging.getLogger().error(e)

            return
        session.commit()
        session.flush()


    @DatabaseHelper._sessionm
    def set_action_status(self, session, sessionid, action_id, uuid, status="DONE"):

        sql = """SELECT count(id) from actionStatus where action_id = :action_id and uuid =:uuid"""
        binds = {"action_id": action_id, "uuid": uuid}
        query = session.execute(text(sql), binds).scalar()
        logger.error(query)
        mode = "update"
        if query is None or query == 0:
            # No status, create it
            mode = "insert"

        binds["status"] = status
        if mode == "update":
            sql = """UPDATE actionStatus set status = :status where action_id = :action_id and uuid =:uuid"""
        else:
            sql = """INSERT INTO actionStatus (action_id, uuid, status) VALUES(:action_id, :uuid, :status)"""

        try:
            session.execute(text(sql), binds)

        except Exception as e:
            session.rollback()
            logging.getLogger().error(e)
            return

        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def get_mastering_script(self, session, script_id):
        sql = """SELECT type, content, payload from scripts where id = :script_id"""
        binds = {"script_id": script_id}

        result = {
            "type":"bash",
            "content":"",
            "payload":""
        }

        query = session.execute(text(sql), binds).all()

        if query == None:
            return result

        _type = "bash"
        payload = None

        templates = {}
        logger.warning(1)
        # Retrieve the template needed to recreate the full payload script
        for e in query:
            logger.warning(2)
            result["type"] = e[0] if e[0] is not None else _type
            result["content"] = e[1] if e[1] is not None else ""

            # For now payload is a compressed base64 json
            _payload = e.payload if e.payload is not None else ""
            _payload = zlib.decompress(base64.b64decode(_payload)).decode("utf-8")

            try:
                payload = json.loads(_payload)
            except Exception as e:
                payload = _payload


            # We successed to load the payload as json
            if isinstance(payload,dict):
                if "script" in payload:
                    # Read once the templates if needed

                    if payload["script"] not in templates:
                        with open(os.path.join(os.path.dirname(__file__), "templates","%s.txt"%payload["script"])) as fb:
                            templates[payload["script"]] = fb.read()
                            fb.close()


                _template = templates[payload["script"]]

                for key in payload:
                    if key == "bloats":
                        substitutions = self.get_bloat_replacements(payload["bloats"])
                        for bloat in substitutions:
                            _template = _template.replace("@@%s@@"%bloat, substitutions[bloat])
                    else:
                        _template = _template.replace("@@%s@@"%key, payload[key])

            unmatched = re.findall("(@@[\\w]@@)", _template)

            # Replace remainings variables by empty or # if the variable starts with Check
            for unmatch in unmatched:
                if unmatch.startswith("@@Check"):
                    _template = _template.replace(unmatch, "#")
                else:
                    _template = _template.replace(unmatch, "")



            try:
                result["payload"] = zlib.compress(_template.encode("utf-8"))
            except Exception as e:
                logger.error("Impossible to compress payload")
            try:
                result["payload"] = base64.b64encode(result["payload"]).decode("utf-8")
            except Exception as e:
                logger.error("Impossible to encode payload in base64")

        return result

    @DatabaseHelper._sessionm
    def get_aes_key(self, session):
        sql = """SELECT valeur from admin.xmpp_conf where section = :section and nom = :name"""
        binds = {"section": "defaultconnection", "name": "keyAES32"}

        result = ""

        query = session.execute(text(sql), binds).all()

        if query == None:
            return result

        for e in query:
            result = e.valeur if e.valeur is not None else ""

        return result


    def get_bloat_replacements(self, bloat_list):
        bloat_remove_packages = {
            "3D Viewer" : ["'Microsoft.Microsoft3DViewer'"],
            "Bing Search" : ["'Microsoft.BingSearch'"],
            "Calculator": ["'Microsoft.WindowsCalculator'"],
            "Camera": ["'Microsoft.WindowsCamera'"],
            "Clipchamp":["'Clipchamp.Clipchamp'"],
            "Clock":["'Microsoft.WindowsAlarms'"],
            "Cortana" : ["'Microsoft.549981C3F5F10'"],
            "Dev Home": ["'Microsoft.Windows.DevHome'"],
            "Family": ["'MicrosoftCorporationII.MicrosoftFamily'"],
            "Feedback Hub" : ["'Microsoft.WindowsFeedbackHub'"],
            "Get Help": ["'Microsoft.GetHelp'"],
            "Handwriting (all languages)": ["'Language.Handwriting'"],
            "Internet Explorer": ["'Browser.InternetExplorer'"],
            "Mail and Calendar": ["'microsoft.windowscommunicationsapps'"],
            "Maps" : ["'Microsoft.WindowsMaps'"],
            "Math Input Panel": ["'MathRecognizer'"],
            "Media Features": ["'MediaPlayback'"],
            "Mixed Reality": ["'Microsoft.MixedReality.Portal'"],
            "Movies & TV" : ["'Microsoft.ZuneVideo'"],
            "News" : ["'Microsoft.BingNews'"],
            "Notepad (modern)" : ["'Microsoft.WindowsNotepad'"],
            "Office 365" : ["'Microsoft.MicrosoftOfficeHub'"],
            "OneNote" : ["'Microsoft.Office.OneNote'"],
            "Outlook for Windows": ["'Microsoft.OutlookForWindows'"],
            "Paint":["'Microsoft.Paint'", "'Microsoft.MSPaint'"],
            "Paint 3D":["'Microsoft.MSPaint'"],
            "People":["'Microsoft.People'"],
            "Photos":["'Microsoft.Windows.Photos'"],
            "powerautomate":["'Microsoft.PowerAutomateDesktop'"],
            "Skype":["'Microsoft.SkypeApp'"],
            "Snipping Tool":["'Microsoft.ScreenSketch'"],"solitairecollection": ["'Microsoft.MicrosoftSolitaireCollection'"],
            "Solitaire Collection": ["'Microsoft.MicrosoftSolitaireCollection'"],
            "Sticky Notes" : ["'Microsoft.MicrosoftStickyNotes'"],
            "Teams" :["'MicrosoftTeams'", "'MSTeams'"],
            "To Do" : ["'Microsoft.Todos'"],
            "Voice Recorder":["'Microsoft.WindowsSoundRecorder'"],
            "Wallet":["'Microsoft.Wallet'"],
            "Weather":["'Microsoft.BingWeather'"],
            "Windows Media Player (modern)" : ["'Microsoft.ZuneMusic'"],
            "Windows Terminal" : ["'Microsoft.WindowsTerminal'"],
            "Xbox Apps" : ["'Microsoft.Xbox.TCUI'", "'Microsoft.XboxApp'", "Microsoft.XboxGameOverlay", "Microsoft.XboxGamingOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.GamingApp"],
            "Your Phone/Phone Link" : ["'Microsoft.YourPhone'"],
        }

        bloat_user_onces = {
            "Copilot": ["""{
            Get-AppxPackage -Name 'Microsoft.Windows.Ai.Copilot.Provider' | Remove-AppxPackage;
        }"""],
        }

        bloat_default_users = {
            "Copilot":["""{
            reg.exe add "HKU\\DefaultUser\\Software\\Policies\\Microsoft\\Windows\\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f;
        }"""],
            "Notepad (modern)": ["""{
            reg.exe add "HKU\\DefaultUser\\Software\\Microsoft\\Notepad" /v ShowStoreBanner /t REG_DWORD /d 0 /f;
        }"""],
            "OneDrive":["Remove-ItemProperty -LiteralPath 'Registry::HKU\\DefaultUser\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'OneDriveSetup' -Force -ErrorAction 'Continue'"],
            "Xbox Apps" : ['reg.exe add "HKU\\DefaultUser\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f;'],
        }

        bloat_specializes = {
            "Dev Home" : ["""{
                Remove-Item -LiteralPath 'Registry::HKLM\\Software\\Microsoft\\WindowsUpdate\\Orchestrator\\UScheduler_Oobe\\DevHomeUpdate' -Force -ErrorAction 'SilentlyContinue';
                }"""],
            "OneDrive":["Remove-Item -LiteralPath 'C:\\Users\\Default\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\OneDrive.lnk', 'C:\\Windows\\System32\\OneDriveSetup.exe', 'C:\\Windows\\SysWOW64\\OneDriveSetup.exe' -ErrorAction 'Continue'"],
            "Outlook for Windows":["Remove-Item -LiteralPath 'Registry::HKLM\\Software\\Microsoft\\WindowsUpdate\\Orchestrator\\UScheduler_Oobe\\OutlookUpdate' -Force -ErrorAction "],
            "Teams" :['reg.exe add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Communications" /v ConfigureChatAutoInstall /t REG_DWORD'],
            "Tips" : ["Get-Content -LiteralPath 'C:\\Windows\\Setup\\Scripts\\RemovePackages.ps1' -Raw | Invoke-Expression"],
            "Windows Fax and Scan":["Get-Content -LiteralPath 'C:\\Windows\\Setup\\Scripts\\RemoveCapabilities.ps1' -Raw | Invoke-Expression;"],
        }

        bloat_remove_capabilities = {
            "OnSync":["'OneCoreUAP.OneSync'"],
            "OpenSsh":["'OpenSSH.Client'"],
            "Paint":["'Microsoft.MSPaint'"],
            "PowerShell ISE":["'Microsoft.Windows.PowerShell.ISE'"],
            "Quick Assist":["'App.Support.QuickAssist'"],
            "Snipping Tool":["'Microsoft.Windows.SnippingTool'"],
            "speech" : ["'Language.Speech'"],
            "Speech (all languages)":["'Language.TextToSpeech'"],
            "Steps Recorder" : ["'App.StepsRecorder'"],
            "Windows Fax and Scan":["'Print.Fax.Scan'"],
            "Windows Hello":["'Hello.Face.18967'","'Hello.Face.Migration.18967'","Hello.Face.20134"],
            "Windows Media Player (classic)" : ["'Media.WindowsMediaPlayer'"],
            "WordPad" : ["'Microsoft.Windows.WordPad'"],
        }

        bloat_remove_features = {
            "PowerShell 2.0":["'MicrosoftWindowsPowerShellV2Root'"],
            "Recall":["'Recall'"],
            "Remote Desktop Client":["'Microsoft-RemoteDesktopConnection'"],
            "Snipping Tool":["'Microsoft-SnippingTool'"],
        }

        result = {
            "BloatsRemovePackages":[],
            "BloatsRemoveCapabilities":[],
            "BloatsRemoveFeatures":[],
            "BloatsSpecialize":[],
            "BloatsUserOnce":[],
            "BloatsDefaultUser":[],
        }

        for bloat in bloat_list:
            if bloat in bloat_remove_packages:
                result["BloatsRemovePackages"] += bloat_remove_packages[bloat]
            if bloat in bloat_remove_capabilities:
                result["BloatsRemoveCapabilities"] += bloat_remove_capabilities[bloat]
            if bloat in bloat_remove_features:
                result["BloatsRemoveFeatures"] += bloat_remove_features[bloat]
            if bloat in bloat_specializes:
                result["BloatsSpecialize"] += bloat_specializes[bloat]
            if bloat in bloat_user_onces:
                result["BloatsUserOnce"] += bloat_user_onces[bloat]
            if bloat in bloat_default_users:
                result["BloatsDefaultUser"] += bloat_default_users[bloat]

        result["BloatsRemovePackages"] = ";\r\n".join(result["BloatsRemovePackages"]) if len(result["BloatsRemovePackages"]) > 0 else ""
        result["BloatsRemoveCapabilities"] = ";\r\n".join(result["BloatsRemoveCapabilities"]) if len(result["BloatsRemoveCapabilities"]) > 0 else ""
        result["BloatsRemoveFeatures"] = ";\r\n".join(result["BloatsRemoveFeatures"]) if len(result["BloatsRemoveFeatures"]) > 0 else ""
        result["BloatsSpecialize"] = ";\r\n".join(result["BloatsSpecialize"]) if len(result["BloatsSpecialize"]) > 0 else ""
        result["BloatsUserOnce"] = ";\r\n".join(result["BloatsUserOnce"]) if len(result["BloatsUserOnce"]) > 0 else ""
        result["BloatsDefaultUser"] = ";\r\n".join(result["BloatsDefaultUser"]) if len(result["BloatsDefaultUser"]) > 0 else ""

        return result
