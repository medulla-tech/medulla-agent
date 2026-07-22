#!/usr/bin/env python3
# file : src/python/xml_sync.py
"""Point d'entree CLI pour injecter/synchroniser un inventaire vers GLPI."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from lib.glpi_xml_sync.config_loader import load_ini_config
from lib.glpi_xml_sync.db import connect_db
from lib.glpi_xml_sync.models import DbConfig, SyncConfig
from lib.glpi_xml_sync.sync_service import process_record
from lib.glpi_xml_sync.xml_parser import parse_inventory


def parse_args() -> argparse.Namespace:
    """Parse les arguments CLI."""
    parser = argparse.ArgumentParser(
        description="Injecte ou synchronise un inventaire XML/JSON/YAML directement dans GLPI (MySQL/MariaDB)"
    )
    parser.add_argument(
        "--config-ini",
        default="",
        help="Chemin d'un fichier INI de configuration (section [glpi_xml_sync])",
    )
    parser.add_argument(
        "--mode",
        choices=["inject", "sync", "auto"],
        help="Mode inject, sync, ou auto (sync si existe, inject sinon)",
    )
    parser.add_argument(
        "--xml-path",
        "--inventory-path",
        dest="xml_path",
        help="Chemin du fichier inventaire XML/JSON/YAML",
    )
    parser.add_argument("--db-host", help="Hote MySQL/MariaDB")
    parser.add_argument("--db-port", type=int, help="Port MySQL (defaut: 3306)")
    parser.add_argument("--db-name", help="Nom de la base GLPI")
    parser.add_argument("--db-user", help="Utilisateur base GLPI")
    parser.add_argument("--db-pass", help="Mot de passe base GLPI")
    parser.add_argument(
        "--default-entity",
        type=int,
        help="entities_id GLPI a utiliser pour les creations (defaut: 0)",
    )
    parser.add_argument(
        "--default-recursive",
        type=int,
        choices=[0, 1],
        help="is_recursive pour glpi_computers (defaut: 0)",
    )
    parser.add_argument(
        "--allow-missing-ocsid",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Autorise un fallback sur DEVICEID si OCSID absent dans le XML",
    )
    parser.add_argument(
        "--dry-run",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Valide/parse sans ecrire en base",
    )
    parser.add_argument(
        "--best-effort",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Ignore les parties mal formees quand une recuperation partielle est possible",
    )
    return parser.parse_args()


def _pick(cli_value: object, ini_value: object, default_value: object) -> object:
    """Retourne la valeur finale avec priorite a la CLI."""
    if cli_value is not None and cli_value != "":
        return cli_value
    if ini_value is not None and ini_value != "":
        return ini_value
    return default_value


def resolve_args(args: argparse.Namespace) -> argparse.Namespace:
    """Fusionne les options CLI avec un INI optionnel."""
    ini_values: dict[str, object] = {}
    config_base_dir: str | None = None
    if args.config_ini:
        ini_path = Path(args.config_ini).expanduser().resolve()
        ini_values = load_ini_config(ini_path)
        config_base_dir = str(ini_path.parent)

    merged = argparse.Namespace(
        mode=_pick(args.mode, ini_values.get("mode"), "auto"),
        xml_path=_pick(args.xml_path, ini_values.get("xml_path"), None),
        db_host=_pick(args.db_host, ini_values.get("db_host"), None),
        db_port=int(_pick(args.db_port, ini_values.get("db_port"), 3306)),
        db_name=_pick(args.db_name, ini_values.get("db_name"), None),
        db_user=_pick(args.db_user, ini_values.get("db_user"), None),
        db_pass=_pick(args.db_pass, ini_values.get("db_pass"), None),
        default_entity=int(_pick(args.default_entity, ini_values.get("default_entity"), 0)),
        default_recursive=int(_pick(args.default_recursive, ini_values.get("default_recursive"), 0)),
        allow_missing_ocsid=bool(
            _pick(args.allow_missing_ocsid, ini_values.get("allow_missing_ocsid"), False)
        ),
        dry_run=bool(_pick(args.dry_run, ini_values.get("dry_run"), False)),
        best_effort=bool(_pick(args.best_effort, ini_values.get("best_effort"), False)),
        config_base_dir=config_base_dir,
    )

    required_keys = [
        "xml_path",
        "db_host",
        "db_name",
        "db_user",
        "db_pass",
    ]
    missing = [key for key in required_keys if getattr(merged, key) in (None, "")]
    if missing:
        raise ValueError(
            "Parametres manquants (CLI ou INI): " + ", ".join(missing)
        )

    if merged.default_recursive not in (0, 1):
        raise ValueError("default_recursive doit valoir 0 ou 1")

    return merged


def main() -> int:
    """Point d'entree du script."""
    raw_args = parse_args()
    try:
        args = resolve_args(raw_args)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"ERREUR: {exc}", file=sys.stderr)
        return 2

    xml_path = Path(args.xml_path).expanduser()
    if not xml_path.is_absolute() and getattr(args, "config_base_dir", None):
        candidate_config_dir = Path(args.config_base_dir) / xml_path
        candidate_repo_root = Path(__file__).resolve().parents[2] / xml_path
        if candidate_config_dir.exists() or not candidate_repo_root.exists():
            xml_path = candidate_config_dir
        else:
            xml_path = candidate_repo_root
    xml_path = xml_path.resolve()

    try:
        records = parse_inventory(
            xml_path,
            allow_missing_ocsid=args.allow_missing_ocsid,
            best_effort=args.best_effort,
        )
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"ERREUR: {exc}", file=sys.stderr)
        return 2

    if not records:
        print(
            json.dumps(
                {
                    "status": "empty",
                    "reason": "Aucune machine exploitable trouvee dans le XML",
                    "xml_path": str(xml_path),
                },
                ensure_ascii=True,
            )
        )
        return 3

    if args.dry_run:
        print(
            json.dumps(
                {
                    "status": "ok",
                    "dry_run": True,
                    "mode": args.mode,
                    "xml_path": str(xml_path),
                    "machines_detected": len(records),
                    "sample": asdict(records[0]),
                },
                ensure_ascii=True,
            )
        )
        return 0

    db_config = DbConfig(
        host=args.db_host,
        port=args.db_port,
        name=args.db_name,
        user=args.db_user,
        password=args.db_pass,
    )
    sync_config = SyncConfig(
        mode=args.mode,
        default_entity=args.default_entity,
        default_recursive=args.default_recursive,
    )

    try:
        conn = connect_db(db_config)
    except RuntimeError as exc:
        print(f"ERREUR: {exc}", file=sys.stderr)
        return 4

    counters = {
        "inserted": 0,
        "updated": 0,
        "sync_created": 0,
        "skipped_existing": 0,
    }

    try:
        cursor = conn.cursor()
        for record in records:
            action = process_record(cursor, record, sync_config)
            counters[action] = counters.get(action, 0) + 1
        conn.commit()
    except Exception as exc:  # pragma: no cover - rollback securite
        conn.rollback()
        print(
            json.dumps(
                {
                    "status": "db_error",
                    "error": str(exc),
                },
                ensure_ascii=True,
            ),
            file=sys.stderr,
        )
        return 5
    finally:
        conn.close()

    print(
        json.dumps(
            {
                "status": "ok",
                "mode": args.mode,
                "machines_processed": len(records),
                "result": counters,
            },
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
