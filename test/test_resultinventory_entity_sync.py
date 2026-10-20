# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : test/test_resultinventory_entity_sync.py

"""Tests de la synchronisation des entites GLPI du plugin resultinventory."""

import ast
import base64
from contextlib import closing
import functools
import importlib.util
import json
import logging
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import zlib

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, event, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker


ROOT = Path(__file__).resolve().parents[1]
SUBSTITUTE = ROOT / "pulse_xmpp_master_substitute"
PLUGIN_PATH = SUBSTITUTE / "pluginsmastersubstitute/plugin_resultinventory.py"
GLPI_VERSIONS = ("Glpi84", "Glpi92", "Glpi93", "Glpi94", "Glpi95", "Glpi100", "Glpi110", "Itsmng21")
Base = declarative_base()


class SourceEntity(Base):
    """Modele de la source federee pour la base isolee."""

    __tablename__ = "local_glpi_entities"
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    completename = Column(String(1024))


class TargetEntity(Base):
    """Modele destination reprenant les champs du schema XMPP."""

    __tablename__ = "glpi_entity"
    id = Column(Integer, primary_key=True)
    glpi_id = Column(Integer, nullable=False)
    name = Column(String(45), nullable=False)
    complete_name = Column(String(512), nullable=False)


class Computer(Base):
    """Table GLPI minimale pour exercer les requetes des huit versions."""

    __tablename__ = "glpi_computers"
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    uuid = Column(String(255))
    entities_id = Column(Integer)
    is_deleted = Column(Integer, default=0)
    is_template = Column(Integer, default=0)


def load_class_methods(path, class_name, methods, namespace):
    """Compile les methodes reelles sans importer les dependances du serveur."""
    tree = ast.parse(path.read_text())
    original = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    selected = [node for node in original.body if isinstance(node, ast.FunctionDef) and node.name in methods]
    if {node.name for node in selected} != set(methods):
        raise AssertionError("Missing methods in %s" % path)
    original.bases = []
    original.body = selected
    isolated = ast.Module(body=[original], type_ignores=[])
    exec(compile(isolated, str(path), "exec"), namespace)
    return namespace[class_name]


def load_plugin():
    """Charge le plugin complet avec dependances runtime simulees."""
    modules = {}
    for name in (
        "lib", "lib.plugins", "lib.plugins.xmpp", "lib.plugins.glpi", "lib.plugins.admin",
        "lib.plugins.dyngroup",
        "lib.glpi_xml_sync", "lib.glpi_xml_sync.db", "lib.glpi_xml_sync.models",
        "lib.glpi_xml_sync.sync_service", "lib.glpi_xml_sync.xml_parser", "lib.utils",
    ):
        modules[name] = types.ModuleType(name)
    for module_name, names in (
        ("lib.plugins.xmpp", ("XmppMasterDatabase",)),
        ("lib.plugins.glpi", ("Glpi",)),
        ("lib.plugins.dyngroup", ("DyngroupDatabase",)),
        ("lib.plugins.admin", ("AdminMasterDatabase",)),
        ("lib.glpi_xml_sync.db", ("connect_db",)),
        ("lib.glpi_xml_sync.models", ("DbConfig", "SyncConfig")),
        ("lib.glpi_xml_sync.sync_service", ("process_record",)),
        ("lib.glpi_xml_sync.xml_parser", ("parse_inventory",)),
    ):
        for name in names:
            setattr(modules[module_name], name, Mock())
    modules["lib.utils"].convert = types.SimpleNamespace(
        convert_bytes_datetime_to_string=lambda value: value.decode() if isinstance(value, bytes) else value
    )
    spec = importlib.util.spec_from_file_location("resultinventory_under_test", PLUGIN_PATH)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class TestEntitySync(unittest.TestCase):
    """Execute les vraies methodes ORM sur SQLite ; seul le verrou est simule."""

    @classmethod
    def setUpClass(cls):
        namespace = {"closing": closing, "text": text, "logger": logging.getLogger(), "Glpi_entity": TargetEntity}
        cls.database_class = load_class_methods(
            SUBSTITUTE / "lib/plugins/xmpp/__init__.py", "XmppMasterDatabase",
            ("_validate_glpi_entity_id", "_validate_glpi_entity_names", "_glpi_entity_needs_sync",
             "_sync_all_glpi_entities", "sync_glpi_entities"), namespace,
        )
        cls.glpi_classes = []
        for version in GLPI_VERSIONS:
            path = SUBSTITUTE / ("lib/plugins/glpi/%s.py" % version)
            namespace = {"functools": functools, "sessionmaker": sessionmaker,
                         "scoped_session": scoped_session, "logging": logging}
            helper = load_class_methods(path, "DatabaseHelper", ("_sessionm",), namespace)
            namespace["DatabaseHelper"] = helper
            cls.glpi_classes.append(
                load_class_methods(path, version, ("getMachineEntityId",), namespace)
            )
        cls.facade_class = load_class_methods(
            SUBSTITUTE / "lib/plugins/glpi/__init__.py", "Glpi", ("getMachineEntityId",), {}
        )
        cls.plugin = load_plugin()

    def setUp(self):
        self.engine = create_engine("sqlite://")
        self.addCleanup(self.engine.dispose)
        self.queries = []
        self.acquired = 1
        self.released = 1
        self.on_acquire = None
        self.invalidations = []
        self.checkouts = 0
        self.checkins = 0
        self.Session = sessionmaker(bind=self.engine)

        @event.listens_for(self.engine, "connect")
        def register_locks(connection, record):
            def acquire(name, timeout):
                if self.on_acquire:
                    self.on_acquire()
                return self.acquired
            connection.create_function("GET_LOCK", 2, acquire)
            connection.create_function("RELEASE_LOCK", 1, lambda name: self.released)

        @event.listens_for(self.engine, "before_cursor_execute")
        def record_query(connection, cursor, statement, parameters, context, executemany):
            self.queries.append(statement)

        @event.listens_for(self.engine, "invalidate")
        def invalidated(connection, record, exception):
            self.invalidations.append(exception)

        @event.listens_for(self.engine, "checkout")
        def checked_out(connection, record, proxy):
            self.checkouts += 1

        @event.listens_for(self.engine, "checkin")
        def checked_in(connection, record):
            self.checkins += 1

        Base.metadata.create_all(self.engine)
        with closing(self.Session()) as session:
            session.add_all([SourceEntity(id=0, name="Root", completename="Root"),
                             SourceEntity(id=5, name="Child", completename="Root > Child")])
            session.commit()
        self.queries.clear()
        self.database = self.database_class()
        self.database.engine_xmppmmaster_base = self.engine
        self.database.Sessionxmpp = self.Session
        self.database.Local_glpi_entities = SourceEntity
        self.glpi = self.glpi_classes[-2]()
        self.glpi.engine_glpi = self.engine
        self.glpi.machine = Computer.__table__
        self.facade = self.facade_class()
        self.facade.version_instance = self.glpi
        self.patch_plugin("XmppMasterDatabase", Mock(return_value=self.database))
        self.patch_plugin("Glpi", Mock(return_value=self.facade))

    def patch_plugin(self, name, value):
        patcher = patch.object(self.plugin, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def seed_target(self, entity_id=5, name="Child", full="Root > Child", internal_id=42):
        with closing(self.Session()) as session:
            session.add(TargetEntity(id=internal_id, glpi_id=entity_id, name=name, complete_name=full))
            session.commit()

    def targets(self):
        with closing(self.Session()) as session:
            return [(row.id, row.glpi_id, row.name, row.complete_name)
                    for row in session.query(TargetEntity).order_by(TargetEntity.glpi_id).all()]

    def test_missing_target_triggers_full_sync_including_root(self):
        self.assertEqual(self.database.sync_glpi_entities(5),
                         {"status": "synchronized", "created": 2, "updated": 0, "unchanged": 0})
        self.assertEqual([row[1] for row in self.targets()], [0, 5])
        self.assertTrue(any("RELEASE_LOCK" in q for q in self.queries))
        self.assertEqual(self.checkouts, self.checkins)

    def test_identical_has_two_targeted_reads_without_lock_or_writes(self):
        self.seed_target()
        self.queries.clear()
        self.assertEqual(self.database.sync_glpi_entities(5), {"status": "unchanged"})
        self.assertEqual(len(self.queries), 2)
        self.assertTrue(all("WHERE" in q for q in self.queries))
        self.assertEqual(self.checkouts, self.checkins)

    def test_name_difference_corrects_all_and_preserves_internal_ids(self):
        self.seed_target(name="Old")
        self.seed_target(entity_id=0, name="Old root", full="Old root", internal_id=91)
        self.assertEqual(self.database.sync_glpi_entities(5)["updated"], 2)
        self.assertEqual(self.targets(),
                         [(91, 0, "Root", "Root"), (42, 5, "Child", "Root > Child")])

    def test_complete_name_only_difference(self):
        self.seed_target(full="Old")
        self.assertEqual(self.database.sync_glpi_entities(5)["updated"], 1)
        self.assertEqual(self.targets()[1], (42, 5, "Child", "Root > Child"))

    def test_manual_and_repeated_calls(self):
        self.assertEqual(self.database.sync_glpi_entities()["created"], 2)
        targets = self.targets()
        self.assertEqual(self.database.sync_glpi_entities()["unchanged"], 2)
        self.assertEqual(self.targets(), targets)

    def test_root_zero_is_target_not_forced_full_sync(self):
        self.seed_target(entity_id=0, name="Root", full="Root")
        self.assertEqual(self.database.sync_glpi_entities(0), {"status": "unchanged"})
        self.assertEqual(len(self.targets()), 1)

    def test_orphan_destination_is_preserved(self):
        self.seed_target(entity_id=99, name="Orphan", full="Orphan")
        self.database.sync_glpi_entities()
        self.assertIn((42, 99, "Orphan", "Orphan"), self.targets())

    def test_missing_source_is_error_without_global_sync(self):
        with self.assertLogs(level="ERROR"), self.assertRaises(LookupError):
            self.database.sync_glpi_entities(999)
        self.assertEqual(len(self.queries), 1)
        self.assertEqual(self.checkouts, self.checkins)

    def test_source_unavailable_does_not_trigger_sync(self):
        SourceEntity.__table__.drop(self.engine)
        self.queries.clear()
        with self.assertLogs(level="ERROR"), self.assertRaises(OperationalError):
            self.database.sync_glpi_entities(5)
        self.assertFalse(any("GET_LOCK" in q for q in self.queries))
        self.assertEqual(self.targets(), [])

    def test_invalid_ids_do_not_query(self):
        for value in (True, -1, "5", 1.5):
            with self.subTest(value=value), self.assertLogs(level="ERROR"), self.assertRaises(ValueError):
                self.database.sync_glpi_entities(value)
        self.assertEqual(self.queries, [])

    def test_invalid_source_names_abort_before_writing(self):
        for field, value in (("name", None), ("name", "n" * 46), ("completename", "f" * 513)):
            with self.subTest(field=field):
                with closing(self.Session()) as session:
                    source = session.query(SourceEntity).filter_by(id=5).one()
                    source.name, source.completename = "Child", "Root > Child"
                    setattr(source, field, value)
                    session.commit()
                with self.assertLogs(level="ERROR"), self.assertRaises(ValueError):
                    self.database.sync_glpi_entities()
                self.assertEqual(self.targets(), [])

    def test_name_length_boundaries(self):
        with closing(self.Session()) as session:
            source = session.query(SourceEntity).filter_by(id=5).one()
            source.name, source.completename = "n" * 45, "f" * 512
            session.commit()
        self.database.sync_glpi_entities(5)
        self.assertEqual(self.targets()[1][2:], ("n" * 45, "f" * 512))

    def test_duplicate_destination_rejected(self):
        self.seed_target()
        self.seed_target(internal_id=43)
        for target in (5, None):
            with self.subTest(target=target), self.assertLogs(level="ERROR"), self.assertRaises(ValueError):
                self.database.sync_glpi_entities(target)
        self.assertEqual(len(self.targets()), 2)

    def test_busy_lock_does_not_write_or_release_foreign_lock(self):
        self.acquired = 0
        with self.assertLogs(level="DEBUG") as logs:
            self.assertEqual(self.database.sync_glpi_entities(5), {"status": "busy"})
        self.assertTrue(all(record.levelno == logging.DEBUG for record in logs.records))
        self.assertFalse(any("RELEASE_LOCK" in q for q in self.queries))
        self.assertEqual(self.targets(), [])

    def test_lock_failure(self):
        self.acquired = None
        with self.assertLogs(level="ERROR"), self.assertRaisesRegex(RuntimeError, "acquire"):
            self.database.sync_glpi_entities(5)
        self.assertEqual(self.targets(), [])

    def test_recheck_avoids_redundant_sync_and_uses_fresh_snapshot(self):
        self.on_acquire = self.seed_target
        self.assertEqual(self.database.sync_glpi_entities(5), {"status": "unchanged"})
        self.assertEqual(len(self.targets()), 1)
        self.assertTrue(any("RELEASE_LOCK" in q for q in self.queries))

    def test_write_failure_rolls_back_and_releases_lock(self):
        self.seed_target(name="Old")
        with self.engine.begin() as connection:
            connection.execute(text(
                "CREATE TRIGGER reject_update BEFORE UPDATE ON glpi_entity "
                "BEGIN SELECT RAISE(ABORT, 'write failed'); END;"
            ))
        with self.assertLogs(level="ERROR"), self.assertRaises(IntegrityError):
            self.database.sync_glpi_entities(5)
        self.assertEqual(self.targets(), [(42, 5, "Old", "Root > Child")])
        self.assertTrue(any("RELEASE_LOCK" in q for q in self.queries))

    def test_release_failure_invalidates_connection(self):
        self.released = 0
        with self.assertLogs(level="ERROR"), self.assertRaisesRegex(RuntimeError, "release"):
            self.database.sync_glpi_entities(5)
        self.assertEqual(len(self.invalidations), 1)

    def test_python_interruption_releases_lock_and_returns_connection(self):
        with patch.object(self.database, "_sync_all_glpi_entities", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.database.sync_glpi_entities(5)
        self.assertTrue(any("RELEASE_LOCK" in q for q in self.queries))
        self.assertEqual(self.targets(), [])
        self.assertEqual(self.checkouts, self.checkins)

    def test_all_glpi_versions_and_facade_read_effective_entity(self):
        with closing(self.Session()) as session:
            session.add_all([Computer(id=23, entities_id=0), Computer(id=25, entities_id=5),
                             Computer(id=24, entities_id=5, is_deleted=1),
                             Computer(id=26, entities_id=5, is_template=1)])
            session.commit()
        for cls in self.glpi_classes:
            with self.subTest(version=cls.__name__):
                version = cls()
                version.engine_glpi, version.machine = self.engine, Computer.__table__
                self.facade.version_instance = version
                self.assertEqual(self.facade.getMachineEntityId(23), 0)
                self.assertEqual(self.facade.getMachineEntityId(25), 5)
                for invalid in (24, 26, 999):
                    with self.assertLogs(level="ERROR"), self.assertRaises(LookupError):
                        self.facade.getMachineEntityId(invalid)
                for invalid in (True, -1, "23"):
                    with self.assertLogs(level="ERROR"), self.assertRaises(ValueError):
                        self.facade.getMachineEntityId(invalid)
                self.assertEqual(self.checkouts, self.checkins)

    def test_invalid_glpi_entity_is_reported(self):
        with closing(self.Session()) as session:
            session.add(Computer(id=23, entities_id=None))
            session.commit()
        with self.assertLogs(level="ERROR"), self.assertRaises(ValueError):
            self.facade.getMachineEntityId(23)

    def test_plugin_calls_database_methods_directly(self):
        glpi, database = Mock(), Mock()
        glpi.getMachineEntityId.return_value = 5
        database.sync_glpi_entities.return_value = {"status": "unchanged"}
        self.patch_plugin("Glpi", Mock(return_value=glpi))
        self.patch_plugin("XmppMasterDatabase", Mock(return_value=database))
        self.assertEqual(self.plugin._sync_inventory_entity(23, "machine@example"), {"status": "unchanged"})
        glpi.getMachineEntityId.assert_called_once_with(23)
        database.sync_glpi_entities.assert_called_once_with(5)
        glpi.engine_glpi.raw_connection.assert_not_called()
        database.engine_xmppmmaster_base.raw_connection.assert_not_called()

    def run_inventory(
        self, mode="forward", computer_id=23, registry=False, dyngroup_error=False,
        old_uuid="UUID23",
    ):
        """Exerce le chemin complet sans injection reseau ni temporisation."""
        database = Mock()
        machine = {
            "id": 12,
            "hostname": "machine",
            "uuid_serial_machine": "setup",
            "uuid_inventorymachine": old_uuid,
        }
        database.getMachinefromjid.return_value = machine
        database.sync_glpi_entities.side_effect = LookupError("source unavailable")
        self.patch_plugin("XmppMasterDatabase", Mock(return_value=database))
        glpi = Mock()
        glpi.getMachineEntityId.return_value = 5
        glpi.getRegistryCollect.return_value = 7
        self.patch_plugin("Glpi", Mock(return_value=glpi))
        self.patch_plugin("getMachineByUuidSetup", Mock(return_value={"id": 23}))
        if computer_id == -1:
            self.patch_plugin("XmppUpdateInventoried", Mock(return_value=-1))
        elif computer_id == -2:
            self.patch_plugin(
                "XmppUpdateInventoried",
                Mock(side_effect=self.plugin.InventoryMachineNotFound("not found")),
            )
        fixer = Mock()
        fixer.get.return_value = "<QUERY>INVENTORY</QUERY><DEVICEID>machine</DEVICEID>"
        self.patch_plugin("InventoryFix", Mock(return_value=fixer))
        self.patch_plugin("_log_runtime_identity_once", Mock())
        self.patch_plugin("send_content", Mock(return_value=(200, b"")))
        self.patch_plugin("_inject_inventory_with_glpi_xml_sync", Mock(return_value=True))
        self.dyngroup = Mock()
        self.dyngroup.reconcilePendingMachineIdentity.return_value = {
            "status": "updated", "merged": 0,
        }
        if dyngroup_error:
            self.dyngroup.reconcilePendingMachineIdentity.side_effect = ValueError(
                "Dyngroup profile conflict: old_uuid=UUID23 new_uuid=UUID42 profiles=[5, 6]"
            )
        self.patch_plugin("DyngroupDatabase", Mock(return_value=self.dyngroup))
        xmpp = types.SimpleNamespace(
            config=types.SimpleNamespace(
                inventory_verbose=False, xmlfixplugindir="/unused", xmldumpactive=False,
                inventory_injection_mode=mode, inventory_enable_forward=True,
                url_to_forward="http://unused", user_agent="test", inventory_plugin="",
            ),
            boundjid=types.SimpleNamespace(bare="substitute@example"),
        )
        payload = {"inventory": base64.b64encode(zlib.compress(fixer.get.return_value.encode()))}
        if registry:
            payload["reginventory"] = base64.b64encode(json.dumps({
                "info": {"max_key_index": 1}, "reg_key_1": {"key": "SOFTWARE\\Example", "value": "value"},
            }).encode())
        with patch.object(self.plugin.time, "sleep"), self.assertLogs(level="ERROR"):
            self.plugin.action(xmpp, "resultinventory", "session", payload,
                               {"from": "machine@example"}, 0, {})
        return database, glpi

    def test_already_correct_uuid_reaches_sync_in_all_modes(self):
        for mode in ("forward", "module", "both"):
            with self.subTest(mode=mode):
                database, glpi = self.run_inventory(mode=mode)
                glpi.getMachineEntityId.assert_called_once_with(23)
                database.sync_glpi_entities.assert_called_once_with(5)
                database.updateMachineidinventory.assert_not_called()
                self.dyngroup.reconcilePendingMachineIdentity.assert_called_once_with(
                    12, "UUID23", "machine"
                )
                self.dyngroup.rememberMachineIdentity.assert_called_once_with(
                    12, "UUID23", "UUID23"
                )

    def test_failed_machine_lookup_does_not_sync(self):
        database, glpi = self.run_inventory(computer_id=-1)
        glpi.getMachineEntityId.assert_not_called()
        database.sync_glpi_entities.assert_not_called()

    def test_missing_machine_exception_is_reported_without_entity_sync(self):
        database, glpi = self.run_inventory(computer_id=-2)
        glpi.getMachineEntityId.assert_not_called()
        database.sync_glpi_entities.assert_not_called()

    def test_machine_lookup_retries_then_uses_unique_hostname(self):
        database = Mock()
        database.listMacAdressforMachine.return_value = ["001122334455"]
        database.updateMachineidinventory.return_value = 1
        glpi = Mock()
        glpi.getMachineByHostname.return_value = [types.SimpleNamespace(id=23)]
        self.patch_plugin("XmppMasterDatabase", Mock(return_value=database))
        self.patch_plugin("Glpi", Mock(return_value=glpi))
        self.patch_plugin("getMachineByUuidSetup", Mock(return_value=None))
        self.patch_plugin("getComputerByMac", Mock(return_value=None))
        machine = {
            "id": 12,
            "jid": "machine@example",
            "hostname": "machine",
            "uuid_serial_machine": "setup",
            "uuid_inventorymachine": "",
        }

        with patch.object(self.plugin.time, "sleep") as sleep:
            result = self.plugin.XmppUpdateInventoried("machine@example", machine)

        self.assertEqual(result, 23)
        self.assertEqual(sleep.call_count, 3)
        glpi.getMachineByHostname.assert_called_once_with("imaging_module", "machine")
        database.updateMachineidinventory.assert_called_once_with("UUID23", 12)

    def test_machine_lookup_raises_when_hostname_fallback_is_ambiguous(self):
        database = Mock()
        database.listMacAdressforMachine.return_value = [""]
        glpi = Mock()
        glpi.getMachineByHostname.return_value = [
            types.SimpleNamespace(id=23),
            types.SimpleNamespace(id=24),
        ]
        self.patch_plugin("XmppMasterDatabase", Mock(return_value=database))
        self.patch_plugin("Glpi", Mock(return_value=glpi))
        self.patch_plugin("getMachineByUuidSetup", Mock(return_value=None))
        machine = {
            "id": 12,
            "jid": "machine@example",
            "hostname": "machine",
            "uuid_serial_machine": "setup",
            "uuid_inventorymachine": "",
        }

        with patch.object(self.plugin.time, "sleep"), self.assertRaises(
            self.plugin.InventoryMachineNotFound
        ):
            self.plugin.XmppUpdateInventoried("machine@example", machine)

        database.updateMachineidinventory.assert_not_called()

    def test_registry_continues_after_sync_error(self):
        database, glpi = self.run_inventory(registry=True)
        glpi.addRegistryCollectContent.assert_called_once_with(23, 7, "Example", "value")

    def test_dyngroup_conflict_is_reported_and_registry_continues(self):
        database, glpi = self.run_inventory(
            registry=True, dyngroup_error=True, old_uuid="UUID42"
        )
        messages = [call.args[0] for call in database.setlogxmpp.call_args_list]
        self.assertTrue(any(
            "Dyngroup identity reconciliation failed" in message
            and "Group memberships and pending UUID links preserved" in message
            for message in messages
        ))
        glpi.addRegistryCollectContent.assert_called_once_with(23, 7, "Example", "value")
        database.sync_glpi_entities.assert_called_once_with(5)
        database.updateMachineidinventory.assert_called_once_with("UUID23", 12)
        self.dyngroup.rememberMachineIdentity.assert_called_once_with(
            12, "UUID42", "UUID23"
        )

    def test_retry_link_is_persisted_before_xmpp_uuid_update(self):
        database, dyngroup = Mock(), Mock()
        calls = Mock()
        calls.attach_mock(dyngroup.rememberMachineIdentity, "remember")
        calls.attach_mock(database.replace_Organization_ad_id_inventory, "organization")
        calls.attach_mock(database.updateMachineidinventory, "update")
        self.patch_plugin("XmppMasterDatabase", Mock(return_value=database))
        self.patch_plugin("DyngroupDatabase", Mock(return_value=dyngroup))
        machine = {"id": 12, "uuid_inventorymachine": "UUID23"}
        self.assertEqual(self.plugin._update_inventory_identity(machine, 42), 42)
        self.assertEqual(
            [(call[0], call[1]) for call in calls.mock_calls],
            [("remember", (12, "UUID23", "UUID42")),
             ("organization", ("UUID23", "UUID42")), ("update", ("UUID42", 12))],
        )
        database.replace_Organization_ad_id_inventory.assert_called_once_with(
            "UUID23", "UUID42"
        )

    def test_queue_failure_does_not_lose_old_xmpp_uuid(self):
        database, dyngroup = Mock(), Mock()
        dyngroup.rememberMachineIdentity.side_effect = RuntimeError("queue unavailable")
        self.patch_plugin("XmppMasterDatabase", Mock(return_value=database))
        self.patch_plugin("DyngroupDatabase", Mock(return_value=dyngroup))
        with self.assertLogs(level="ERROR"):
            self.assertEqual(self.plugin._update_inventory_identity(
                {"id": 12, "uuid_inventorymachine": "UUID23"}, 42
            ), -1)
        database.updateMachineidinventory.assert_not_called()

    def test_xmpp_update_failure_is_not_reported_as_success(self):
        database, dyngroup = Mock(), Mock()
        database.updateMachineidinventory.return_value = -1
        self.patch_plugin("XmppMasterDatabase", Mock(return_value=database))
        self.patch_plugin("DyngroupDatabase", Mock(return_value=dyngroup))
        with self.assertLogs(level="ERROR"):
            self.assertEqual(self.plugin._update_inventory_identity(
                {"id": 12, "uuid_inventorymachine": "UUID23"}, 42
            ), -1)
        dyngroup.rememberMachineIdentity.assert_called_once_with(
            12, "UUID23", "UUID42"
        )
        database.replace_Organization_ad_id_inventory.assert_called_once_with(
            "UUID23", "UUID42"
        )

    def test_organization_failure_keeps_old_xmpp_uuid_for_retry(self):
        database, dyngroup = Mock(), Mock()
        database.replace_Organization_ad_id_inventory.return_value = -1
        self.patch_plugin("XmppMasterDatabase", Mock(return_value=database))
        self.patch_plugin("DyngroupDatabase", Mock(return_value=dyngroup))
        machine = {"id": 12, "uuid_inventorymachine": "UUID23"}
        with self.assertLogs(level="ERROR"):
            self.assertEqual(self.plugin._update_inventory_identity(machine, 42), -1)
        database.updateMachineidinventory.assert_not_called()
        database.replace_Organization_ad_id_inventory.return_value = 1
        self.assertEqual(self.plugin._update_inventory_identity(machine, 42), 42)
        database.updateMachineidinventory.assert_called_once_with("UUID42", 12)

    def test_plugin_identity_and_version(self):
        self.assertEqual(self.plugin.plugin["NAME"], "resultinventory")
        self.assertEqual(self.plugin.plugin["VERSION"], "1.21")


class TestGlpiSetupUuidLookup(unittest.TestCase):
    def test_recreated_machine_ignores_deleted_and_template_records(self):
        engine = create_engine("sqlite://")
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        with closing(factory()) as session:
            session.add_all([
                Computer(id=1, uuid="hardware-uuid", is_deleted=1),
                Computer(id=2, uuid="hardware-uuid", is_template=1),
                Computer(id=3, uuid="hardware-uuid"),
                Computer(id=4, uuid="deleted-only", is_deleted=1),
                Computer(id=5, uuid="template-only", is_template=1),
            ])
            session.commit()
        for version in GLPI_VERSIONS:
            with self.subTest(version=version):
                cls = load_class_methods(
                    SUBSTITUTE / ("lib/plugins/glpi/%s.py" % version), version,
                    ("getMachineByUuidSetup",),
                    {"Machine": Computer, "create_session": factory},
                )
                database = cls()
                database._machineobject = lambda row: {"id": row.id} if row else {}
                self.assertEqual(
                    database.getMachineByUuidSetup("hardware-uuid"), {"id": 3}
                )
                self.assertEqual(database.getMachineByUuidSetup("deleted-only"), {})
                self.assertEqual(database.getMachineByUuidSetup("template-only"), {})
                self.assertEqual(database.getMachineByUuidSetup("missing"), {})


class TestGlpiHostnameLookup(unittest.TestCase):
    def test_imaging_lookup_is_exact_and_filters_inactive_rows_in_all_versions(self):
        engine = create_engine("sqlite://")
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        with closing(factory()) as session:
            session.add_all([
                Computer(id=1, name="machine", entities_id=0),
                Computer(id=2, name="machine", entities_id=5),
                Computer(id=3, name="machine-extra", entities_id=0),
                Computer(id=4, name="machine", is_deleted=1),
                Computer(id=5, name="machine", is_template=1),
            ])
            session.commit()
        for version in GLPI_VERSIONS:
            with self.subTest(version=version):
                cls = load_class_methods(
                    SUBSTITUTE / ("lib/plugins/glpi/%s.py" % version), version,
                    ("getMachineByHostname", "__filter_on", "__filter_on_filter",
                     "__filter_on_entity"),
                    {"Machine": Computer, "create_session": factory},
                )
                database = cls()
                database.machine = Computer.__table__
                database.config = types.SimpleNamespace(filter_on=None)
                self.assertEqual(
                    {row.id for row in database.getMachineByHostname(
                        "imaging_module", "machine"
                    )}, {1, 2},
                )
                entity_filter = Mock(side_effect=lambda query, ctx: query.filter(
                    Computer.entities_id == 5
                ))
                setattr(database, "_%s__filter_on_entity" % version, entity_filter)
                self.assertEqual(
                    [row.id for row in database.getMachineByHostname(
                        "user-context", "machine"
                    )], [2],
                )
                entity_filter.assert_called_once()


class TestDyngroupAccess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database_class = load_class_methods(
            SUBSTITUTE / "lib/plugins/dyngroup/__init__.py",
            "DyngroupDatabase",
            (
                "getAllMachinesUuid", "updateNewNames", "reconcileMachineIdentity",
                "_reconcileMachineIdentity", "ensureIdentityQueue",
                "rememberMachineIdentity", "reconcilePendingMachineIdentity",
            ),
            {
                "text": text, "MetaData": MetaData,
                "Table": Table, "Column": Column,
                "Integer": Integer, "String": String,
            },
        )

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.engine = create_engine("sqlite:///" + directory.name + "/dyngroup.db")
        self.addCleanup(self.engine.dispose)
        with self.engine.begin() as connection:
            connection.execute(text("PRAGMA foreign_keys = ON"))
            connection.execute(
                text(
                    "CREATE TABLE Machines "
                    "(id INTEGER PRIMARY KEY, uuid VARCHAR(64), name VARCHAR(255))"
                )
            )
            connection.execute(text(
                "CREATE TABLE Results (id INTEGER PRIMARY KEY, FK_groups INTEGER, "
                "FK_machines INTEGER REFERENCES Machines(id))"
            ))
            connection.execute(text(
                "CREATE TABLE ProfilesResults (FK_groups INTEGER, "
                "FK_machines INTEGER PRIMARY KEY REFERENCES Machines(id))"
            ))
            connection.execute(
                text("INSERT INTO Machines (uuid, name) VALUES (:uuid, :name)"),
                {"uuid": "UUID23", "name": "old-name"},
            )
        self.database = self.database_class()
        self.database.engine_dyngroup_base = self.engine
        self.database.ensureIdentityQueue()

    def test_reads_and_updates_machine_name_cache(self):
        self.assertEqual(self.database.getAllMachinesUuid(), {"UUID23": "old-name"})
        self.assertEqual(
            self.database.updateNewNames({"UUID23": "new-name", "": "ignored"}),
            1,
        )
        self.assertEqual(self.database.getAllMachinesUuid(), {"UUID23": "new-name"})

    def seed_memberships(self, target_profile=5):
        with self.engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO Machines VALUES (2, 'UUID42', 'new-name')"
            ))
            connection.execute(text(
                "INSERT INTO Results VALUES (1, 10, 1), (2, 10, 2), (3, 11, 2)"
            ))
            connection.execute(text(
                "INSERT INTO ProfilesResults VALUES (5, 1), (:profile, 2)"
            ), {"profile": target_profile})

    def snapshot(self):
        with self.engine.connect() as connection:
            return {
                table: [tuple(row) for row in connection.execute(
                    text("SELECT * FROM %s ORDER BY 1" % table)
                )]
                for table in ("Machines", "Results", "ProfilesResults")
            }

    def test_uuid_change_preserves_internal_id_and_links(self):
        with self.engine.begin() as connection:
            connection.execute(text("INSERT INTO Results VALUES (1, 10, 1)"))
            connection.execute(text("INSERT INTO ProfilesResults VALUES (5, 1)"))
        self.assertEqual(
            self.database.reconcileMachineIdentity("UUID23", "UUID42", "renamed"),
            {"status": "updated", "merged": 0},
        )
        self.assertEqual(self.snapshot(), {
            "Machines": [(1, "UUID42", "renamed")],
            "Results": [(1, 10, 1)],
            "ProfilesResults": [(5, 1)],
        })

    def test_merge_unions_groups_and_identical_profiles_and_is_repeatable(self):
        self.seed_memberships()
        self.assertEqual(
            self.database.reconcileMachineIdentity("UUID23", "UUID42", "renamed"),
            {"status": "updated", "merged": 1},
        )
        expected = {
            "Machines": [(1, "UUID42", "renamed")],
            "Results": [(1, 10, 1), (3, 11, 1)],
            "ProfilesResults": [(5, 1)],
        }
        self.assertEqual(self.snapshot(), expected)
        self.database.reconcileMachineIdentity("UUID23", "UUID42", "renamed")
        self.assertEqual(self.snapshot(), expected)

    def test_conflicting_profiles_leave_all_rows_unchanged(self):
        self.seed_memberships(target_profile=6)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "profile conflict"):
            self.database.reconcileMachineIdentity("UUID23", "UUID42", "renamed")
        self.assertEqual(self.snapshot(), before)

    def test_target_only_profile_moves_to_preserved_source_id(self):
        self.seed_memberships()
        with self.engine.begin() as connection:
            connection.execute(text(
                "DELETE FROM ProfilesResults WHERE FK_machines = 1"
            ))
        self.database.reconcileMachineIdentity("UUID23", "UUID42", "renamed")
        self.assertEqual(self.snapshot()["ProfilesResults"], [(5, 1)])

    def test_existing_target_is_kept_when_source_is_missing(self):
        with self.engine.begin() as connection:
            connection.execute(text("INSERT INTO Results VALUES (1, 10, 1)"))
        self.database.reconcileMachineIdentity("UUID99", "UUID23", "renamed")
        self.assertEqual(self.snapshot()["Machines"], [(1, "UUID23", "renamed")])
        self.assertEqual(self.snapshot()["Results"], [(1, 10, 1)])

    def test_database_failure_rolls_back_membership_merge(self):
        self.seed_memberships()
        with self.engine.begin() as connection:
            connection.execute(text(
                "CREATE TRIGGER reject_identity BEFORE UPDATE ON Machines "
                "BEGIN SELECT RAISE(ABORT, 'identity update failed'); END"
            ))
        before = self.snapshot()
        with self.assertRaises(IntegrityError):
            self.database.reconcileMachineIdentity("UUID23", "UUID42", "renamed")
        self.assertEqual(self.snapshot(), before)

    def test_missing_cache_does_not_recreate_memberships(self):
        before = self.snapshot()
        self.assertEqual(
            self.database.reconcileMachineIdentity("UUID90", "UUID91", "missing"),
            {"status": "missing", "merged": 0},
        )
        self.assertEqual(self.snapshot(), before)

    def pending(self):
        with self.engine.connect() as connection:
            return [tuple(row) for row in connection.execute(text(
                "SELECT xmpp_machine_id, old_uuid, new_uuid "
                "FROM substitute_pending_machine_identity ORDER BY old_uuid"
            ))]

    def test_pending_survives_conflict_and_restarts_until_resolved(self):
        self.seed_memberships(target_profile=6)
        before = self.snapshot()
        self.database.rememberMachineIdentity(12, "UUID23", "UUID42")
        with self.assertRaisesRegex(ValueError, "profile conflict"):
            self.database.reconcilePendingMachineIdentity(12, "UUID42", "renamed")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.pending(), [(12, "UUID23", "UUID42")])

        restarted = self.database_class()
        restarted.engine_dyngroup_base = create_engine(self.engine.url)
        self.addCleanup(restarted.engine_dyngroup_base.dispose)
        restarted.ensureIdentityQueue()
        # XMPP already carries UUID42; this must not discard the pending UUID23.
        restarted.rememberMachineIdentity(12, "UUID42", "UUID42")
        with self.engine.begin() as connection:
            connection.execute(text(
                "UPDATE ProfilesResults SET FK_groups = 5 WHERE FK_machines = 2"
            ))
        restarted.reconcilePendingMachineIdentity(12, "UUID42", "renamed")
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.snapshot()["Machines"], [(1, "UUID42", "renamed")])
        self.assertEqual(self.snapshot()["Results"], [(1, 10, 1), (3, 11, 1)])

    def test_second_uuid_change_preserves_all_pending_sources(self):
        self.database.rememberMachineIdentity(12, "UUID23", "UUID42")
        self.database.rememberMachineIdentity(12, "UUID42", "UUID50")
        self.assertEqual(self.pending(), [
            (12, "UUID23", "UUID50"), (12, "UUID42", "UUID50"),
        ])
        self.database.reconcilePendingMachineIdentity(12, "UUID50", "renamed")
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.snapshot()["Machines"], [(1, "UUID50", "renamed")])

    def test_multiple_pending_sources_merge_existing_machine_entries(self):
        self.seed_memberships()
        self.database.rememberMachineIdentity(12, "UUID23", "UUID42")
        self.database.rememberMachineIdentity(12, "UUID42", "UUID50")
        self.database.reconcilePendingMachineIdentity(12, "UUID50", "renamed")
        state = self.snapshot()
        self.assertEqual(len(state["Machines"]), 1)
        machine_id, uuid, hostname = state["Machines"][0]
        self.assertEqual((uuid, hostname), ("UUID50", "renamed"))
        self.assertEqual(
            {(row[1], row[2]) for row in state["Results"]},
            {(10, machine_id), (11, machine_id)},
        )
        self.assertEqual(state["ProfilesResults"], [(5, machine_id)])
        self.assertEqual(self.pending(), [])

    def test_sql_failure_preserves_pending_and_memberships(self):
        self.seed_memberships()
        self.database.rememberMachineIdentity(12, "UUID23", "UUID42")
        with self.engine.begin() as connection:
            connection.execute(text(
                "CREATE TRIGGER reject_queue_delete BEFORE DELETE "
                "ON substitute_pending_machine_identity "
                "BEGIN SELECT RAISE(ABORT, 'queue delete failed'); END"
            ))
        before = self.snapshot()
        with self.assertRaises(IntegrityError):
            self.database.reconcilePendingMachineIdentity(12, "UUID42", "renamed")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.pending(), [(12, "UUID23", "UUID42")])

    def test_later_pending_conflict_rolls_back_all_reconciliations(self):
        self.seed_memberships(target_profile=6)
        self.database.rememberMachineIdentity(12, "UUID23", "UUID42")
        self.database.rememberMachineIdentity(12, "UUID42", "UUID50")
        before = self.snapshot()
        pending = self.pending()

        with self.assertRaisesRegex(ValueError, "profile conflict"):
            self.database.reconcilePendingMachineIdentity(12, "UUID50", "renamed")

        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.pending(), pending)

    def test_pending_target_mismatch_does_not_modify_memberships(self):
        self.database.rememberMachineIdentity(12, "UUID23", "UUID42")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "target changed"):
            self.database.reconcilePendingMachineIdentity(12, "UUID99", "renamed")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.pending(), [(12, "UUID23", "UUID42")])


if __name__ == "__main__":
    unittest.main()
