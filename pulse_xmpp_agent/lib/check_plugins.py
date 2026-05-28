#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file pulse_xmpp_agent/lib/check_plugins.py
"""
Verification de l'integrite des plugins pulse_xmpp_agent.

Utilisable de deux facons:

1) Comme module, depuis un plugin ou n'importe quel code Python:

    from lib.check_plugins import check_plugins
    report = check_plugins()
    if not report["ok"]:
        for d in report["details"]:
            if d["status"] == "KO":
                print(d["file"], d["errors"])

2) Comme programme autonome:

    # Linux
    python3 -m lib.check_plugins
    python3 -m lib.check_plugins --errors-only

    # Windows
    "c:\\Program Files\\Python3\\python.exe" -m lib.check_plugins
"""

import argparse
import glob
import importlib.util
import os
import py_compile
import sys
from pathlib import Path

# Racine du package pulse_xmpp_agent = deux niveaux au-dessus de ce fichier
# pulse_xmpp_agent/lib/check_plugins.py -> parent -> lib -> parent -> pulse_xmpp_agent
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent

_CLI_DESCRIPTION = (
        "Verifie l'integrite des plugins pulse_xmpp_agent "
        "(compilation, import, descripteur plugin, action, coherence NAME/fichier)."
)

_CLI_EPILOG = """
Utilisation rapide
    - Mode standard: liste tous les plugins (OK + KO)
    - --errors-only: affiche uniquement les erreurs
    - --details: affiche les metadonnees des plugins OK (NAME, VERSION, TYPE)

Exemples CMD (Windows)
    C:\\Program Files\\Python3\\python.exe -m lib.check_plugins
    C:\\Program Files\\Python3\\python.exe -m lib.check_plugins --errors-only
    C:\\Program Files\\Python3\\python.exe -m lib.check_plugins --details
    C:\\Program Files\\Python3\\python.exe -m lib.check_plugins --dir "C:\\Program Files\\Python3\\Lib\\site-packages\\pulse_xmpp_agent\\agentrescue\\pluginsmachine"

Exemples PowerShell (Windows)
    & "C:\\Program Files\\Python3\\python.exe" -m lib.check_plugins
    & "C:\\Program Files\\Python3\\python.exe" -m lib.check_plugins --errors-only
    & "C:\\Program Files\\Python3\\python.exe" -m lib.check_plugins --details
    & "C:\\Program Files\\Python3\\python.exe" -m lib.check_plugins --dir "C:\\Program Files\\Python3\\Lib\\site-packages\\pulse_xmpp_agent\\agentrescue\\pluginsmachine"

Exemple Linux
    python3 -m lib.check_plugins --errors-only

Mode module Python
    from lib.check_plugins import check_plugins
    report = check_plugins()
"""


def _resolve_plugin_dirs(plugin_dir, package_root):
    """Retourne la liste des dossiers de plugins a verifier."""
    if plugin_dir is None:
        candidates = [
            package_root / "pluginsmachine",
            package_root / "agentrescue" / "pluginsmachine",
        ]
        return [p for p in candidates if p.exists()]

    if isinstance(plugin_dir, (list, tuple, set)):
        return [Path(p) for p in plugin_dir]

    # Autorise une liste separee par ';' pour la CLI (--dir "path1;path2")
    if isinstance(plugin_dir, str) and ";" in plugin_dir:
        return [Path(p.strip()) for p in plugin_dir.split(";") if p.strip()]

    return [Path(plugin_dir)]


def check_plugins(plugin_dir=None, package_root=None):
    """
    Verifie tous les fichiers plugin_*.py dans plugin_dir.

    Args:
        plugin_dir (str|Path|None):
            Dossier des plugins a verifier.
            Par defaut: <package_root>/pluginsmachine
        package_root (str|Path|None):
            Racine du package pour resoudre les imports "from lib.xxx".
            Par defaut: dossier pulse_xmpp_agent/ detecte automatiquement.

    Returns:
        dict:
            ok      (bool)  : True si tous les plugins passent.
            summary (str)   : ex "12/14 plugins OK, 2 KO"
            total   (int)   : nombre de plugins trouves.
            passed  (int)   : plugins valides.
            failed  (int)   : plugins en erreur.
            details (list)  : liste de dict par plugin (voir ci-dessous).

        Chaque entree de details:
            file           (str)  : chemin absolu du fichier.
            compile_ok     (bool) : compilation reussie.
            import_ok      (bool) : chargement du module reussi.
            plugin_dict_ok (bool) : variable plugin de type dict presente.
            action_ok      (bool) : fonction action callable presente.
            name_ok        (bool) : meta NAME correspond au nom de fichier.
            errors         (list) : liste des messages d'erreur.
            status         (str)  : "OK" ou "KO".
    """
    if package_root is None:
        package_root = _PACKAGE_ROOT
    package_root = Path(package_root)

    plugin_dirs = _resolve_plugin_dirs(plugin_dir, package_root)

    # Injecte la racine dans sys.path pour que "from lib.xxx import" fonctionne
    package_root_str = str(package_root)
    if package_root_str not in sys.path:
        sys.path.insert(0, package_root_str)

    files = []
    for pdir in plugin_dirs:
        files.extend(sorted(pdir.glob("plugin_*.py")))

    if not files:
        searched = ", ".join(str(p) for p in plugin_dirs) if plugin_dirs else "(aucun dossier)"
        return {
            "ok": False,
            "summary": f"Aucun fichier plugin_*.py trouve dans {searched}",
            "total": 0,
            "passed": 0,
            "failed": 0,
            "plugin_dirs": [str(p) for p in plugin_dirs],
            "details": [],
        }

    results = []

    for p in files:
        item = {
            "file": str(p),
            "compile_ok": False,
            "import_ok": False,
            "plugin_dict_ok": False,
            "action_ok": False,
            "name_ok": False,
            "errors": [],
            "status": "KO",
        }

        # 1. Compilation syntaxique
        try:
            py_compile.compile(str(p), doraise=True)
            item["compile_ok"] = True
        except Exception as e:
            item["errors"].append(f"compile: {e}")

        # 2. Chargement du module
        module = None
        if item["compile_ok"]:
            try:
                mod_name = p.stem + "_plugincheck"
                spec = importlib.util.spec_from_file_location(mod_name, str(p))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                item["import_ok"] = True
            except Exception as e:
                item["errors"].append(f"import: {e}")

        # 3. Controles metadonnees + action
        if item["import_ok"]:
            meta = getattr(module, "plugin", None)
            action = getattr(module, "action", None)

            item["plugin_dict_ok"] = isinstance(meta, dict)
            item["action_ok"] = callable(action)

            if item["plugin_dict_ok"]:
                meta_name = str(meta.get("NAME", ""))
                expected_file_name = f"plugin_{meta_name}.py"
                item["name_ok"] = p.name == expected_file_name
                item["meta"] = {
                    "NAME": meta.get("NAME"),
                    "VERSION": meta.get("VERSION"),
                    "TYPE": meta.get("TYPE"),
                }
                if not item["name_ok"]:
                    item["errors"].append(
                        "nom de fichier incoherent avec plugin['NAME']: "
                        f"attendu={expected_file_name!r} trouve={p.name!r} "
                        f"(NAME={meta_name!r})"
                    )
            else:
                item["errors"].append("variable 'plugin' manquante ou pas un dict")

            if not item["action_ok"]:
                item["errors"].append("fonction 'action' manquante ou non callable")

        item["status"] = "OK" if (
            item["compile_ok"]
            and item["import_ok"]
            and item["plugin_dict_ok"]
            and item["action_ok"]
            and item["name_ok"]
        ) else "KO"

        results.append(item)

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "OK")
    failed = total - passed

    return {
        "ok": failed == 0,
        "summary": f"{passed}/{total} plugins OK, {failed} KO",
        "total": total,
        "passed": passed,
        "failed": failed,
        "plugin_dirs": [str(p) for p in plugin_dirs],
        "details": results,
    }


def _main():
    parser = argparse.ArgumentParser(
        prog="python -m lib.check_plugins",
        description=_CLI_DESCRIPTION,
        epilog=_CLI_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dir",
        default=None,
        metavar="PATH",
        help=(
            "Chemin du dossier plugins, ou liste separee par ';' "
            "(defaut: pluginsmachine/ et agentrescue/pluginsmachine si present)"
        ),
    )
    parser.add_argument(
        "--errors-only",
        action="store_true",
        help="N'affiche que les plugins KO.",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Affiche aussi les metadonnees (NAME, VERSION, TYPE) des plugins OK.",
    )
    args = parser.parse_args()

    report = check_plugins(plugin_dir=args.dir)

    print(f"\n[check_plugins] {report['summary']}")
    print(f"  package_root : {_PACKAGE_ROOT}")
    if args.dir:
        print(f"  plugin_dir   : {args.dir}")
    else:
        print(f"  plugin_dirs  : {', '.join(report.get('plugin_dirs', []))}")
    print()

    for d in report["details"]:
        if args.errors_only and d["status"] == "OK":
            continue
        label = "OK " if d["status"] == "OK" else "KO "
        print(f"  {label}  {Path(d['file']).name}")
        if args.details and d["status"] == "OK":
            m = d.get("meta", {})
            print(
                f"         NAME={m.get('NAME')!r}  "
                f"VERSION={m.get('VERSION')!r}  "
                f"TYPE={m.get('TYPE')!r}"
            )
        for err in d["errors"]:
            print(f"       ! {err}")

    print()
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(_main())
