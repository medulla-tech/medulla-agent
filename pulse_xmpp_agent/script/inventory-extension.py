#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Inventory-BrowserExtensions-Addins.py
---------------------------------------
Inventorie les extensions installées dans :
  - Google Chrome, Chromium, Brave, Microsoft Edge  (moteur Chromium)
  - Mozilla Firefox
  - Apple Safari                                     (macOS uniquement)
  - Mozilla Thunderbird
  - Microsoft Office add-ins COM & Web               (Windows / macOS)

Compatibilité : Python 3.11 – 3.13 | Windows · Linux · macOS

Usage :
  python Inventory-BrowserExtensions-Addins.py
  python Inventory-BrowserExtensions-Addins.py --format json --output /tmp/inventaire
  python Inventory-BrowserExtensions-Addins.py --format console --include-internal -v
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import platform
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

# Module disponible uniquement sur Windows
if sys.platform == "win32":
    import winreg  # type: ignore[import]

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"

# Identifiants d'extensions internes Gecko à exclure par défaut
_INTERNAL_GECKO_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"@mozilla\.org",
        r"@firefox\.com",
        r"firefox@getpocket\.com",
        r"@mozilla-org",
        r"formautofill@mozilla\.org",
        r"webcompat@mozilla\.org",
        r"screenshots@mozilla\.org",
        r"doh-rollout@mozilla\.org",
    )
]

# ══════════════════════════════════════════════════════════════════════════════
# MODÈLE DE DONNÉES
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ExtensionEntry:
    """Représente une extension ou un add-in inventorié."""

    date_inventaire: str
    ordinateur: str
    utilisateur: str
    os_name: str
    source: str
    categorie: str
    extension_id: str
    nom: str
    version: str
    description: str
    auteur: str
    profil: str
    actif: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)  # type: ignore[return-value]


# ══════════════════════════════════════════════════════════════════════════════
# CONTEXTE SYSTÈME
# ══════════════════════════════════════════════════════════════════════════════


def _os_name() -> str:
    match sys.platform:
        case "win32":
            return "Windows"
        case "darwin":
            return "macOS"
        case _:
            return "Linux"


def _current_user() -> str:
    return os.environ.get("USERNAME") or os.environ.get("USER") or "inconnu"


def _computer_name() -> str:
    return platform.node() or "inconnu"


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS CHROMIUM
# ══════════════════════════════════════════════════════════════════════════════


def _resolve_chromium_locale(ver_dir: Path, msg_key: str) -> str | None:
    """Résout un nom localisé __MSG_key__ depuis les fichiers _locales."""
    locales_dir = ver_dir / "_locales"
    if not locales_dir.is_dir():
        return None
    for locale in ("en", "en_US", "fr", "de"):
        msg_file = locales_dir / locale / "messages.json"
        if msg_file.is_file():
            try:
                msgs: dict[str, dict[str, str]] = json.loads(
                    msg_file.read_text(encoding="utf-8", errors="replace")
                )
                for k, v in msgs.items():
                    if k.lower() == msg_key.lower():
                        return v.get("message") or None
            except (json.JSONDecodeError, OSError):
                pass
    return None


def _chromium_extension_states(profile_dir: Path) -> dict[str, dict]:
    """Lit l'état activé/désactivé des extensions via le fichier Preferences."""
    prefs_file = profile_dir / "Preferences"
    if not prefs_file.is_file():
        return {}
    try:
        prefs: dict = json.loads(
            prefs_file.read_text(encoding="utf-8", errors="replace")
        )
        return prefs.get("extensions", {}).get("settings", {})
    except (json.JSONDecodeError, OSError):
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# COLLECTE — NAVIGATEURS CHROMIUM
# ══════════════════════════════════════════════════════════════════════════════

_CHROMIUM_SKIP_IDS = frozenset({
    "Temp",
    "nmmhkkegccagdldgiimedpiccmgmieda",  # Widevine
    "mhjfbmdgcfjbbpaeojofohoefgiehjai",  # Chrome PDF Viewer
})

_PROFILE_DIR_RE = re.compile(
    r"^(Default|Profile \d+|Guest Profile|System Profile)$"
)


def collect_chromium_extensions(
    browser_name: str,
    user_data_path: Path,
    context: dict[str, str],
) -> list[ExtensionEntry]:
    """Inventorie les extensions d'un navigateur basé sur Chromium."""
    results: list[ExtensionEntry] = []

    if not user_data_path.is_dir():
        logging.debug("[%s] Chemin introuvable : %s", browser_name, user_data_path)
        return results

    logging.info("    [%s] %s", browser_name, user_data_path)

    profile_dirs = [
        d
        for d in user_data_path.iterdir()
        if d.is_dir() and _PROFILE_DIR_RE.match(d.name)
    ]

    for profile_dir in profile_dirs:
        ext_dir = profile_dir / "Extensions"
        if not ext_dir.is_dir():
            continue

        states = _chromium_extension_states(profile_dir)

        for ext_folder in ext_dir.iterdir():
            if not ext_folder.is_dir():
                continue

            ext_id = ext_folder.name
            if ext_id in _CHROMIUM_SKIP_IDS:
                continue

            # Trier les dossiers de version, traiter uniquement le plus récent
            ver_dirs = sorted(
                (d for d in ext_folder.iterdir() if d.is_dir()),
                reverse=True,
            )

            for ver_dir in ver_dirs:
                manifest_path = ver_dir / "manifest.json"
                if not manifest_path.is_file():
                    continue

                try:
                    manifest: dict = json.loads(
                        manifest_path.read_text(encoding="utf-8", errors="replace")
                    )
                except (json.JSONDecodeError, OSError) as exc:
                    logging.debug(
                        "[%s] Erreur manifest %s : %s", browser_name, manifest_path, exc
                    )
                    continue

                # Résolution du nom localisé
                raw_name: str = manifest.get("name", ext_id)
                if m := re.match(r"^__MSG_(.+)__$", raw_name):
                    ext_name = _resolve_chromium_locale(ver_dir, m.group(1)) or ext_id
                else:
                    ext_name = raw_name

                # Description (ignorer les clés localisées non résolues)
                raw_desc: str = manifest.get("description", "")
                ext_desc = "" if raw_desc.startswith("__MSG_") else raw_desc

                # Auteur
                ext_author = str(manifest.get("author", ""))

                # État activé/désactivé
                # Par défaut : si l'extension est présente sur disque avec un
                # manifest valide, elle est considérée active. On ne passe à
                # "Non" que si Preferences le confirme explicitement.
                enabled = "Oui"
                if ext_id in states:
                    s: dict = states[ext_id]
                    if "state" in s:
                        # state 1 = activée, 0 = désactivée, autres valeurs = activée
                        enabled = "Non" if s["state"] == 0 else "Oui"
                    elif "enabled" in s:
                        enabled = "Oui" if s["enabled"] else "Non"
                    elif "disable_reasons" in s and s["disable_reasons"]:
                        # Clé présente avec raisons de désactivation
                        enabled = "Non"

                results.append(
                    ExtensionEntry(
                        date_inventaire=context["now"],
                        ordinateur=context["computer"],
                        utilisateur=context["user"],
                        os_name=context["os"],
                        source=browser_name,
                        categorie="Extension Navigateur",
                        extension_id=ext_id,
                        nom=ext_name,
                        version=manifest.get("version", ""),
                        description=ext_desc[:200],
                        auteur=ext_author,
                        profil=str(profile_dir),
                        actif=enabled,
                    )
                )
                break  # On ne traite que la version la plus récente

    return results


# ══════════════════════════════════════════════════════════════════════════════
# COLLECTE — GECKO (Firefox / Thunderbird)
# ══════════════════════════════════════════════════════════════════════════════

_GECKO_TYPE_MAP: dict[str, str] = {
    "extension":  "Extension Navigateur",
    "theme":      "Thème",
    "locale":     "Pack de langue",
    "dictionary": "Dictionnaire",
}


def collect_gecko_extensions(
    app_name: str,
    profiles_base: Path,
    context: dict[str, str],
    include_internal: bool = False,
) -> list[ExtensionEntry]:
    """Inventorie les extensions d'une application Gecko (Firefox, Thunderbird)."""
    results: list[ExtensionEntry] = []

    if not profiles_base.is_dir():
        logging.debug("[%s] Chemin introuvable : %s", app_name, profiles_base)
        return results

    logging.info("    [%s] %s", app_name, profiles_base)

    for profile_dir in profiles_base.iterdir():
        if not profile_dir.is_dir():
            continue

        ext_json = profile_dir / "extensions.json"
        if not ext_json.is_file():
            continue

        try:
            data: dict = json.loads(
                ext_json.read_text(encoding="utf-8", errors="replace")
            )
        except (json.JSONDecodeError, OSError) as exc:
            logging.debug(
                "[%s] Erreur extensions.json %s : %s", app_name, ext_json, exc
            )
            continue

        for addon in data.get("addons", []):
            addon_id: str = addon.get("id", "")
            if not addon_id:
                continue

            if not include_internal:
                if any(p.search(addon_id) for p in _INTERNAL_GECKO_PATTERNS):
                    continue

            default_locale: dict = addon.get("defaultLocale") or {}
            addon_name    = default_locale.get("name")        or addon_id
            addon_desc    = default_locale.get("description") or ""
            addon_author  = default_locale.get("creator")     or ""
            addon_version = addon.get("version", "")

            active_val = addon.get("active")
            if active_val is True or active_val == 1:
                enabled = "Oui"
            elif active_val is False or active_val == 0:
                enabled = "Non"
            else:
                # Champ absent ou None : l'addon est dans extensions.json
                # donc installé — on suppose actif par défaut
                enabled = "Oui"
            ext_type = _GECKO_TYPE_MAP.get(
                addon.get("type", "extension"), "Extension Navigateur"
            )

            results.append(
                ExtensionEntry(
                    date_inventaire=context["now"],
                    ordinateur=context["computer"],
                    utilisateur=context["user"],
                    os_name=context["os"],
                    source=app_name,
                    categorie=ext_type,
                    extension_id=addon_id,
                    nom=str(addon_name),
                    version=addon_version,
                    description=str(addon_desc)[:200],
                    auteur=addon_author,
                    profil=str(profile_dir),
                    actif=enabled,
                )
            )

    return results


# ══════════════════════════════════════════════════════════════════════════════
# COLLECTE — SAFARI (macOS uniquement)
# ══════════════════════════════════════════════════════════════════════════════


def collect_safari_extensions(context: dict[str, str]) -> list[ExtensionEntry]:
    """Inventorie les extensions Safari (macOS uniquement)."""
    results: list[ExtensionEntry] = []

    if sys.platform != "darwin":
        logging.debug("[Safari] Non applicable sur %s", sys.platform)
        return results

    logging.info("    [Safari] Lecture des extensions macOS")

    home = Path.home()
    ext_paths = [
        home / "Library/Safari/Extensions",
        home / "Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions",
        home / "Library/Containers/com.apple.Safari/Data/Library/Safari/Extensions",
    ]

    seen_ids: set[str] = set()

    for ext_path in ext_paths:
        if not ext_path.is_dir():
            continue
        for item in ext_path.iterdir():
            if item.suffix in (".db", ".plist", ".json"):
                continue
            if item.name in seen_ids:
                continue
            seen_ids.add(item.name)

            results.append(
                ExtensionEntry(
                    date_inventaire=context["now"],
                    ordinateur=context["computer"],
                    utilisateur=context["user"],
                    os_name=context["os"],
                    source="Safari",
                    categorie="Extension Navigateur",
                    extension_id=item.name,
                    nom=item.stem,
                    version="N/A",
                    description="",
                    auteur="",
                    profil=str(ext_path),
                    actif="Inconnu",
                )
            )

    # pluginkit — extensions Safari App actives
    try:
        proc = subprocess.run(
            ["pluginkit", "-m", "-A", "-p", "com.apple.Safari.extension"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in proc.stdout.splitlines():
            m = re.match(r"^\+\s+(.+?)\((.+?)\)", line)
            if m:
                bundle_id = m.group(1).strip()
                version   = m.group(2).strip()
                if bundle_id not in seen_ids:
                    seen_ids.add(bundle_id)
                    results.append(
                        ExtensionEntry(
                            date_inventaire=context["now"],
                            ordinateur=context["computer"],
                            utilisateur=context["user"],
                            os_name=context["os"],
                            source="Safari",
                            categorie="Extension Navigateur",
                            extension_id=bundle_id,
                            nom=bundle_id,
                            version=version,
                            description="",
                            auteur="",
                            profil="pluginkit",
                            actif="Oui",
                        )
                    )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logging.debug("[Safari] pluginkit non disponible")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS OFFICE XML
# ══════════════════════════════════════════════════════════════════════════════


def _parse_office_xml_manifest(xml_file: Path, source: str, context: dict[str, str]) -> ExtensionEntry | None:
    """Parse un manifeste XML de Web Add-in Office et retourne une entrée ou None."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as exc:
        logging.debug("[%s] Erreur XML %s : %s", source, xml_file, exc)
        return None

    # Extraction du namespace
    ns_match = re.match(r"\{(.+?)\}", root.tag)
    ns = f"{{{ns_match.group(1)}}}" if ns_match else ""

    def _txt(tag: str) -> str:
        el = root.find(f"{ns}{tag}")
        return el.text.strip() if el is not None and el.text else ""

    # Certains manifestes utilisent DefaultValue comme attribut
    display_name = _txt("DisplayName")
    dn_el = root.find(f".//{ns}DefaultValue")
    if not display_name and dn_el is not None:
        display_name = dn_el.get("DefaultValue", "") or dn_el.text or ""
    display_name = display_name or xml_file.stem

    return ExtensionEntry(
        date_inventaire=context["now"],
        ordinateur=context["computer"],
        utilisateur=context["user"],
        os_name=context["os"],
        source=source,
        categorie="Web Add-in Office",
        extension_id=xml_file.stem,
        nom=display_name.strip(),
        version=_txt("Version"),
        description=_txt("Description")[:200],
        auteur=_txt("ProviderName"),
        profil=str(xml_file.parent),
        actif="Oui",
    )


# ══════════════════════════════════════════════════════════════════════════════
# COLLECTE — MICROSOFT OFFICE (Windows)
# ══════════════════════════════════════════════════════════════════════════════

_OFFICE_APPS     = ("Word", "Excel", "PowerPoint", "Outlook", "Access", "OneNote",
                    "Publisher", "Project", "Visio")
_OFFICE_VERSIONS = ("16.0", "15.0", "14.0")
# LoadBehavior : valeurs paires = non chargé, valeurs impaires = chargé
# -1 = clé absente (add-in enregistré donc supposé actif)
# 0/2 = non chargé  |  1 = à la demande  |  3/9 = auto-load actif
# 8/16/24 = désactivé par l'utilisateur ou le gestionnaire d'add-ins
_LOAD_BEHAVIOR_DISABLED = frozenset({0, 2, 8, 16, 24, 64})
_LOAD_BEHAVIOR_DEMAND   = frozenset({1})


def _winreg_str(key: "winreg.HKEYType", name: str, default: str = "") -> str:
    """Lit une valeur de registre comme chaîne, retourne default si absente."""
    try:
        val, _ = winreg.QueryValueEx(key, name)
        return str(val)
    except OSError:
        return default


def collect_office_addins_windows(context: dict[str, str]) -> list[ExtensionEntry]:
    """Inventorie les add-ins COM et Web de Microsoft Office sur Windows."""
    results: list[ExtensionEntry] = []

    logging.info("    [Office] Lecture des add-ins COM (registre Windows)")

    for version in _OFFICE_VERSIONS:
        for app in _OFFICE_APPS:
            reg_paths: list[tuple[int, str]] = [
                (winreg.HKEY_CURRENT_USER,  rf"Software\Microsoft\Office\{version}\{app}\Addins"),
                (winreg.HKEY_LOCAL_MACHINE, rf"Software\Microsoft\Office\{version}\{app}\Addins"),
                (winreg.HKEY_LOCAL_MACHINE, rf"Software\Wow6432Node\Microsoft\Office\{version}\{app}\Addins"),
            ]
            for hive, reg_path in reg_paths:
                try:
                    with winreg.OpenKey(hive, reg_path) as parent_key:
                        idx = 0
                        while True:
                            try:
                                addin_subkey_name = winreg.EnumKey(parent_key, idx)
                                idx += 1
                            except OSError:
                                break
                            try:
                                with winreg.OpenKey(parent_key, addin_subkey_name) as addin_key:
                                    load_behavior_str = _winreg_str(addin_key, "LoadBehavior", "-1")
                                    try:
                                        lb = int(load_behavior_str)
                                    except ValueError:
                                        lb = -1
                                    if lb == -1:
                                        # Clé LoadBehavior absente : add-in
                                        # enregistré donc considéré actif
                                        enabled = "Oui"
                                    elif lb in _LOAD_BEHAVIOR_DISABLED:
                                        enabled = "Non"
                                    elif lb in _LOAD_BEHAVIOR_DEMAND:
                                        enabled = "À la demande"
                                    else:
                                        # Valeurs impaires (3, 9, 11…) = chargé
                                        enabled = "Oui" if lb % 2 != 0 else "Non"
                                    friendly = _winreg_str(addin_key, "FriendlyName") or addin_subkey_name
                                    desc     = _winreg_str(addin_key, "Description")
                                    ver      = _winreg_str(addin_key, "Version")

                                results.append(
                                    ExtensionEntry(
                                        date_inventaire=context["now"],
                                        ordinateur=context["computer"],
                                        utilisateur=context["user"],
                                        os_name=context["os"],
                                        source=f"Office {app} ({version})",
                                        categorie="Add-in COM Office",
                                        extension_id=addin_subkey_name,
                                        nom=friendly,
                                        version=ver,
                                        description=desc[:200],
                                        auteur="",
                                        profil=reg_path,
                                        actif=enabled,
                                    )
                                )
                            except OSError as exc:
                                logging.debug(
                                    "[Office] Erreur sous-clé %s : %s", addin_subkey_name, exc
                                )
                except OSError:
                    pass  # Clé absente = normal

    # ── Web Add-ins (WEF) ───────────────────────────────────────────────────
    logging.info("    [Office] Lecture des Web Add-ins (WEF)")

    local_app = Path(os.environ.get("LOCALAPPDATA", ""))
    wef_paths = [
        local_app / "Microsoft/Office/16.0/Wef",
        local_app / "Microsoft/Office/root/Wef",
    ]
    for wef_path in wef_paths:
        if not wef_path.is_dir():
            continue
        for xml_file in wef_path.rglob("*.xml"):
            entry = _parse_office_xml_manifest(xml_file, "Office Web Add-in", context)
            if entry:
                results.append(entry)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# COLLECTE — MICROSOFT OFFICE (macOS)
# ══════════════════════════════════════════════════════════════════════════════

_MACOS_WEF_RE = re.compile(r"[Ww]ef|[Aa]ddin|[Ee]xtension", re.IGNORECASE)


def collect_office_addins_macos(context: dict[str, str]) -> list[ExtensionEntry]:
    """Inventorie les Web Add-ins de Microsoft Office sur macOS."""
    results: list[ExtensionEntry] = []

    logging.info("    [Office] Lecture des Web Add-ins (macOS)")

    home = Path.home()
    group_container = home / "Library/Group Containers/UBF8T346G9.Office"

    if not group_container.is_dir():
        logging.debug("[Office macOS] Conteneur de groupe introuvable : %s", group_container)
        return results

    for xml_file in group_container.rglob("*.xml"):
        if not _MACOS_WEF_RE.search(xml_file.parent.name):
            continue
        entry = _parse_office_xml_manifest(xml_file, "Office Web Add-in (macOS)", context)
        if entry:
            results.append(entry)

    # Scripts d'application Office macOS
    for app_id in ("com.microsoft.Word", "com.microsoft.Excel",
                   "com.microsoft.Powerpoint", "com.microsoft.Outlook"):
        scripts_dir = home / f"Library/Application Scripts/{app_id}"
        if not scripts_dir.is_dir():
            continue
        for item in scripts_dir.iterdir():
            results.append(
                ExtensionEntry(
                    date_inventaire=context["now"],
                    ordinateur=context["computer"],
                    utilisateur=context["user"],
                    os_name=context["os"],
                    source=f"Office Script macOS ({app_id})",
                    categorie="Script Office",
                    extension_id=item.name,
                    nom=item.stem,
                    version="",
                    description="",
                    auteur="",
                    profil=str(scripts_dir),
                    actif="Inconnu",
                )
            )

    return results


# ══════════════════════════════════════════════════════════════════════════════
# EXPORT
# ══════════════════════════════════════════════════════════════════════════════


def export_csv(results: list[ExtensionEntry], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f, fieldnames=list(results[0].as_dict().keys()), delimiter=";"
        )
        writer.writeheader()
        writer.writerows(r.as_dict() for r in results)
    print(f"CSV exporté  : {path}")


def export_json(results: list[ExtensionEntry], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump([r.as_dict() for r in results], f, ensure_ascii=False, indent=2)
    print(f"JSON exporté : {path}")


def print_console(results: list[ExtensionEntry]) -> None:
    if not results:
        print("Aucun résultat.")
        return
    W = {"source": 32, "nom": 42, "version": 14, "actif": 10}
    header = (
        f"{'SOURCE':<{W['source']}} {'NOM':<{W['nom']}} "
        f"{'VERSION':<{W['version']}} {'ACTIF':<{W['actif']}}"
    )
    print("\n" + header)
    print("─" * len(header))
    for r in results:
        print(
            f"{r.source[:W['source']]:<{W['source']}} "
            f"{r.nom[:W['nom']]:<{W['nom']}} "
            f"{r.version[:W['version']]:<{W['version']}} "
            f"{r.actif:<{W['actif']}}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# CLIENT GLPI
# ══════════════════════════════════════════════════════════════════════════════


class GlpiClient:
    """
    Client REST GLPI minimal — stdlib uniquement (aucune dépendance tierce).

    Prérequis GLPI :
      - API REST activée : Configuration > Générale > API
      - App-Token créé dans la même section
      - User-Token visible dans le profil utilisateur GLPI
      - Le poste doit déjà exister dans GLPI (identifié par son nom)

    Gère :
      - Ouverture / fermeture de session (context manager)
      - Recherche d'un poste (Computer)
      - Création / recherche d'un logiciel (Software) et de sa version
      - Liaison logiciel ↔ poste (Item_SoftwareVersion)
    """

    def __init__(
        self,
        base_url: str,
        app_token: str,
        user_token: str,
        verify_ssl: bool = True,
    ) -> None:
        self.base_url   = base_url.rstrip("/")
        # Accepter indifféremment https://glpi.exemple.fr  ou
        # https://glpi.exemple.fr/apirest.php — on normalise vers la racine.
        if self.base_url.endswith("/apirest.php"):
            self.base_url = self.base_url[: -len("/apirest.php")]
        self.app_token  = app_token
        self.user_token = user_token
        self._session_token: str | None = None
        if verify_ssl:
            self._ssl_ctx: ssl.SSLContext = ssl.create_default_context()
        else:
            self._ssl_ctx = ssl._create_unverified_context()  # noqa: SLF001
            logging.warning("[GLPI] Vérification SSL désactivée.")

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "GlpiClient":
        self._open_session()
        return self

    def __exit__(self, *_: object) -> None:
        self._close_session()

    def _open_session(self) -> None:
        resp = self._request(
            "GET",
            "initSession",
            extra_headers={"Authorization": f"user_token {self.user_token}"},
        )
        # GLPI retourne une liste ["ERROR_CODE", "message"] en cas d'erreur
        if isinstance(resp, list):
            code = resp[0] if resp else "ERREUR_INCONNUE"
            msg  = resp[1] if len(resp) > 1 else ""
            raise RuntimeError(
                f"[GLPI] initSession refusé : {code} — {msg}\n"
                "  → Vérifiez l'App-Token (Configuration > Générale > API)\n"
                "  → Vérifiez le User-Token (Profil utilisateur > Jeton API)"
            )
        if not isinstance(resp, dict) or "session_token" not in resp:
            raise RuntimeError(
                f"[GLPI] Réponse initSession inattendue — clé 'session_token' absente.\n"
                f"  Réponse reçue : {resp}\n"
                "  → Vérifiez l'URL GLPI et que l'API REST est activée."
            )
        token = str(resp["session_token"]).strip()
        if not token:
            raise RuntimeError(
                "[GLPI] Session token reçu est vide.\n"
                "  → Le User-Token GLPI est peut-être révoqué ou invalide."
            )
        self._session_token = token
        logging.info("[GLPI] Session ouverte (token: %s…)", token[:8])

    def _close_session(self) -> None:
        try:
            self._request("GET", "killSession")
            logging.info("[GLPI] Session fermée.")
        except Exception:  # noqa: BLE001
            pass

    # ── Appels HTTP ───────────────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        endpoint: str,
        extra_headers: dict[str, str] | None = None,
        body: dict | None = None,
    ) -> dict | list:
        url = f"{self.base_url}/apirest.php/{endpoint}"
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "App-Token":    self.app_token,
        }
        if self._session_token:
            headers["Session-Token"] = self._session_token
        if extra_headers:
            headers.update(extra_headers)

        data = json.dumps(body).encode("utf-8") if body else None
        req  = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                if not raw.strip():
                    return {}
                parsed = json.loads(raw)
                # GLPI retourne parfois une liste ["ERROR_CODE", "msg"] avec HTTP 200
                if isinstance(parsed, list) and parsed and isinstance(parsed[0], str) and parsed[0].startswith("ERROR_"):
                    raise RuntimeError(
                        f"[GLPI] Erreur API : {parsed[0]} — {parsed[1] if len(parsed) > 1 else ''}"
                    )
                return parsed
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode("utf-8", errors="replace")
            # Essayer de parser le corps JSON de l'erreur GLPI
            try:
                glpi_err = json.loads(body_err)
                if isinstance(glpi_err, list) and glpi_err:
                    err_code = glpi_err[0]
                    err_msg  = glpi_err[1] if len(glpi_err) > 1 else ""
                    hint = ""
                    if err_code == "ERROR_SESSION_TOKEN_MISSING":
                        hint = "\n  → La session GLPI n'a pas pu être établie. Vérifiez App-Token et User-Token."
                    elif err_code == "ERROR_NOT_LOGGED":
                        hint = "\n  → Session expirée ou invalide."
                    elif err_code == "ERROR_APP_TOKEN_PARAMETERS_MISSING":
                        hint = "\n  → App-Token manquant ou invalide."
                    raise RuntimeError(
                        f"HTTP {exc.code} [{method} {endpoint}]: {err_code} — {err_msg}{hint}"
                    ) from exc
            except (json.JSONDecodeError, IndexError):
                pass
            raise RuntimeError(
                f"HTTP {exc.code} [{method} {endpoint}]: {body_err}"
            ) from exc

    # ── Helpers métier ────────────────────────────────────────────────────────

    def get_computer_id(self, name: str) -> int | None:
        """Recherche un ordinateur par nom, retourne son id GLPI ou None."""
        encoded = urllib.parse.quote(name)
        result  = self._request("GET", f"Computer?searchText[name]={encoded}&range=0-5")
        if isinstance(result, list) and result:
            return int(result[0]["id"])
        return None

    def get_or_create_software(self, name: str, comment: str = "") -> int:
        """Retourne l'id du logiciel existant ou en crée un nouveau."""
        encoded = urllib.parse.quote(name)
        result  = self._request("GET", f"Software?searchText[name]={encoded}&range=0-1")
        if isinstance(result, list) and result:
            return int(result[0]["id"])
        created = self._request(
            "POST", "Software",
            body={"input": {"name": name, "comment": comment}},
        )
        logging.debug("[GLPI] Logiciel créé : '%s' (id=%s)", name, created.get("id"))
        return int(created["id"])

    def get_or_create_software_version(self, software_id: int, version: str) -> int:
        """Retourne l'id de la version existante ou en crée une nouvelle."""
        ver     = version or "N/A"
        enc_ver = urllib.parse.quote(ver)
        result  = self._request(
            "GET",
            f"SoftwareVersion?searchText[softwares_id]={software_id}"
            f"&searchText[name]={enc_ver}&range=0-1",
        )
        if isinstance(result, list) and result:
            return int(result[0]["id"])
        created = self._request(
            "POST", "SoftwareVersion",
            body={"input": {"softwares_id": software_id, "name": ver}},
        )
        logging.debug(
            "[GLPI] Version '%s' créée pour logiciel id=%s", ver, software_id
        )
        return int(created["id"])

    def link_software_to_computer(
        self, computer_id: int, software_version_id: int
    ) -> bool:
        """
        Lie une version de logiciel à un ordinateur.
        Retourne True si le lien a été créé, False s'il existait déjà.
        """
        result = self._request(
            "GET",
            f"Item_SoftwareVersion"
            f"?searchText[items_id]={computer_id}"
            f"&searchText[itemtype]=Computer"
            f"&searchText[softwareversions_id]={software_version_id}"
            f"&range=0-1",
        )
        if isinstance(result, list) and result:
            return False  # Lien déjà présent
        self._request(
            "POST",
            "Item_SoftwareVersion",
            body={
                "input": {
                    "itemtype":            "Computer",
                    "items_id":            computer_id,
                    "softwareversions_id": software_version_id,
                    "is_dynamic":          0,  # non géré par l'agent GLPI → jamais supprimé automatiquement
                }
            },
        )
        return True


# ══════════════════════════════════════════════════════════════════════════════
# GLPI INVENTORY PLUGIN — FORMAT & INJECTION
# ══════════════════════════════════════════════════════════════════════════════

# Mapping catégorie interne → system_category GLPI Inventory
_CATEGORY_TO_GLPI: dict[str, str] = {
    "Extension Navigateur": "browser extensions",
    "Thème":                "browser themes",
    "Pack de langue":       "browser language packs",
    "Dictionnaire":         "browser dictionaries",
    "Add-in COM Office":    "office add-ins",
    "Web Add-in Office":    "office web add-ins",
    "Script Office":        "office scripts",
}


def build_glpi_inventory_payload(
    results: list[ExtensionEntry],
    computer_name: str,
) -> dict:
    """
    Construit le payload JSON au format GLPI Inventory Agent (GLPI 10+).

    Comportement add-only :
      - partial=True  : GLPI ajoute les logiciels envoyés sans supprimer
                        ceux déjà présents pour ce poste.
      - deviceid stable (sans horodatage) : GLPI retrouve toujours le même
        agent/poste à chaque exécution — indispensable pour ne pas créer un
        doublon de poste à chaque run.
      - Seule la section 'hardware.name' est envoyée pour identifier le poste ;
        aucune autre donnée existante (OS, utilisateur, matériel…) n'est touchée.

    Référence : https://github.com/glpi-project/inventory_format
    """
    # deviceid stable = même poste reconnu à chaque exécution
    deviceid = f"{computer_name}-BrowserExtInventory"

    softwares = []
    for entry in results:
        soft: dict[str, object] = {
            "name":            f"[{entry.source}] {entry.nom}",
            "version":         entry.version or "N/A",
            "publisher":       entry.auteur or entry.source,
            "comments":        (
                f"ID: {entry.extension_id} | "
                f"Categorie: {entry.categorie} | "
                f"Actif: {entry.actif} | "
                f"Profil: {entry.profil}"
            )[:255],
            "system_category": _CATEGORY_TO_GLPI.get(
                entry.categorie, "plugins & extensions"
            ),
            "from":            "inventory",
        }
        softwares.append(soft)

    return {
        "action":   "inventory",
        "deviceid": deviceid,
        "itemtype": "Computer",
        "partial":  True,
        "content": {
            "versionclient": "GLPI-BrowserExt-Injector/1.0",
            "hardware": {
                "name": computer_name,   # identifiant du poste uniquement
            },
            "softwares": softwares,
        },
    }


def push_via_glpi_inventory_plugin(
    results: list[ExtensionEntry],
    glpi_url: str,
    computer_name: str,
    dry_run: bool = False,
    verify_ssl: bool = True,
) -> None:
    """
    Injecte l'inventaire via le plugin GLPI Inventory (mode add-only).

    Envoie un POST JSON à {glpi_url}/front/inventory.php.
    Les logiciels envoyés sont ajoutés à l'inventaire GLPI existant du poste
    sans écraser ni supprimer aucune autre donnée (OS, matériel, utilisateur…).

    Aucun token d'authentification requis — le plugin fait confiance
    aux agents réseau (comme le ferait le GLPI Agent).

    Prérequis côté GLPI :
      - Plugin "GLPI Inventory" installé et activé
      - Autoriser les inventaires non authentifiés (ou configurer un token
        d'agent si le plugin le requiert)
    """
    endpoint_url = f"{glpi_url.rstrip('/')}/front/inventory.php"
    payload      = build_glpi_inventory_payload(results, computer_name)
    mode_label   = "[DRY-RUN] " if dry_run else ""

    print(
        f"\n{mode_label}[GLPI Inventory] Envoi de {len(results)} logiciels "
        f"vers {endpoint_url} ..."
    )

    if dry_run:
        logging.debug(
            "[DRY-RUN] Payload GLPI Inventory :\n%s",
            json.dumps(payload, ensure_ascii=False, indent=2)[:2000],
        )
        print(
            f"[DRY-RUN] {len(results)} entrées seraient envoyées "
            f"(deviceid: {payload['deviceid']})."
        )
        return

    # Contexte SSL
    if verify_ssl:
        ssl_ctx: ssl.SSLContext = ssl.create_default_context()
    else:
        ssl_ctx = ssl._create_unverified_context()  # noqa: SLF001
        logging.warning("[GLPI Inventory] Vérification SSL désactivée.")

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req  = urllib.request.Request(
        endpoint_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=60) as resp:
            raw        = resp.read().decode("utf-8", errors="replace").strip()
            http_code  = resp.status
            logging.debug("[GLPI Inventory] HTTP %s — réponse : %s", http_code, raw[:200])

            if http_code in (200, 201):
                print(
                    f"[GLPI Inventory] Inventaire accepté (HTTP {http_code}). "
                    f"deviceid : {payload['deviceid']}"
                )
            else:
                print(f"[GLPI Inventory] Réponse inattendue HTTP {http_code} : {raw[:200]}")

    except urllib.error.HTTPError as exc:
        body_err = exc.read().decode("utf-8", errors="replace")
        hint = ""
        if exc.code == 403:
            hint = (
                "\n  → Vérifiez que le plugin GLPI Inventory est activé et"
                " autorise les inventaires entrants."
            )
        elif exc.code == 404:
            hint = (
                "\n  → Endpoint introuvable. Vérifiez que le plugin GLPI Inventory"
                " est installé (/front/inventory.php)."
            )
        print(f"[GLPI Inventory] ERREUR HTTP {exc.code} : {body_err[:300]}{hint}")

    except (urllib.error.URLError, OSError) as exc:
        print(f"[GLPI Inventory] Connexion échouée : {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# ENVOI VERS GLPI (REST API)
# ══════════════════════════════════════════════════════════════════════════════


def push_to_glpi(
    results: list[ExtensionEntry],
    glpi_url: str,
    app_token: str,
    user_token: str,
    computer_name: str,
    dry_run: bool = False,
    verify_ssl: bool = True,
) -> None:
    """
    Envoie l'inventaire vers GLPI via l'API REST.

    Chaque extension est créée comme un logiciel (Software) avec sa version
    et liée au poste cible via Item_SoftwareVersion.
    Le nom du logiciel suit le format : "[Source] Nom"
    (ex : "[Firefox] uBlock Origin", "[Office Outlook (16.0)] Acrobat PDFMaker")
    """
    mode_label = "[DRY-RUN] " if dry_run else ""
    print(f"\n{mode_label}[GLPI] Envoi de {len(results)} entrées vers {glpi_url} ...")

    try:
        with GlpiClient(glpi_url, app_token, user_token, verify_ssl) as client:

            # ── Recherche du poste ────────────────────────────────────────────
            computer_id = client.get_computer_id(computer_name)
            if computer_id is None:
                print(
                    f"[GLPI] ERREUR : poste '{computer_name}' introuvable dans GLPI.\n"
                    "       Vérifiez que le nom correspond exactement à l'entrée GLPI."
                )
                return

            print(f"[GLPI] Poste '{computer_name}' trouvé (id={computer_id}).")

            created_count  = 0
            existing_count = 0
            error_count    = 0

            for entry in results:
                # Nom du logiciel : "[Source] Nom" pour regrouper par navigateur/app
                soft_name = f"[{entry.source}] {entry.nom}"
                comment   = (
                    f"Catégorie : {entry.categorie} | "
                    f"ID extension : {entry.extension_id} | "
                    f"Auteur : {entry.auteur} | "
                    f"Profil : {entry.profil}"
                )

                if dry_run:
                    logging.debug(
                        "[DRY-RUN] Serait envoyé : %s v%s", soft_name, entry.version
                    )
                    created_count += 1
                    continue

                try:
                    soft_id = client.get_or_create_software(soft_name, comment)
                    ver_id  = client.get_or_create_software_version(soft_id, entry.version)
                    created = client.link_software_to_computer(computer_id, ver_id)
                    if created:
                        created_count += 1
                    else:
                        existing_count += 1
                except Exception as exc:  # noqa: BLE001
                    logging.warning("[GLPI] Erreur pour '%s' : %s", soft_name, exc)
                    error_count += 1

            print(
                f"[GLPI] Terminé — Créés : {created_count} | "
                f"Déjà présents : {existing_count} | Erreurs : {error_count}"
            )

    except Exception as exc:  # noqa: BLE001
        print(f"[GLPI] Connexion échouée : {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════════════════


def _build_chromium_paths(home: Path) -> dict[str, Path]:
    match sys.platform:
        case "win32":
            base = Path(os.environ.get("LOCALAPPDATA", ""))
            return {
                "Google Chrome":  base / "Google/Chrome/User Data",
                "Chromium":       base / "Chromium/User Data",
                "Brave":          base / "BraveSoftware/Brave-Browser/User Data",
                "Microsoft Edge": base / "Microsoft/Edge/User Data",
            }
        case "darwin":
            base = home / "Library/Application Support"
            return {
                "Google Chrome":  base / "Google/Chrome",
                "Chromium":       base / "Chromium",
                "Brave":          base / "BraveSoftware/Brave-Browser",
                "Microsoft Edge": base / "Microsoft Edge",
            }
        case _:  # Linux
            return {
                "Google Chrome":  home / ".config/google-chrome",
                "Chromium":       home / ".config/chromium",
                "Brave":          home / ".config/BraveSoftware/Brave-Browser",
                "Microsoft Edge": home / ".config/microsoft-edge",
            }


def _build_firefox_path(home: Path) -> Path:
    match sys.platform:
        case "win32":
            return Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles"
        case "darwin":
            return home / "Library/Application Support/Firefox/Profiles"
        case _:
            return home / ".mozilla/firefox"


def _build_thunderbird_path(home: Path) -> Path:
    match sys.platform:
        case "win32":
            return Path(os.environ.get("APPDATA", "")) / "Thunderbird/Profiles"
        case "darwin":
            return home / "Library/Thunderbird/Profiles"
        case _:
            return home / ".thunderbird"


def main() -> None:
    # Forcer UTF-8 sur stdout/stderr pour éviter UnicodeEncodeError sur Windows
    # (terminal cp1252 par défaut ne supporte pas les caractères de dessin de boîtes)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    parser = argparse.ArgumentParser(
        description="Inventaire multi-OS des extensions navigateurs et add-ins Office/Thunderbird",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python Inventory-BrowserExtensions-Addins.py\n"
            "  python Inventory-BrowserExtensions-Addins.py --format json\n"
            "  python Inventory-BrowserExtensions-Addins.py --format console -v\n"
        ),
    )
    parser.add_argument(
        "--output", "-o",
        default=f"Inventaire_Extensions_{timestamp}",
        metavar="CHEMIN",
        help="Chemin de base des fichiers de sortie sans extension (défaut : Inventaire_Extensions_<horodatage>)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["csv", "json", "console", "all"],
        default="all",
        help="Format d'export : csv | json | console | all (défaut : all)",
    )
    parser.add_argument(
        "--include-internal",
        action="store_true",
        help="Inclure les composants internes Firefox/Thunderbird",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Afficher les messages de débogage",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    # ── Arguments GLPI (tous optionnels) ─────────────────────────────────────
    glpi_group = parser.add_argument_group(
        "GLPI",
        "Paramètres d'envoi vers GLPI (optionnels — l'inventaire local fonctionne sans).",
    )
    glpi_group.add_argument(
        "--glpi-url",
        metavar="URL",
        help="URL de base du serveur GLPI (ex : https://glpi.mondomaine.fr)",
    )
    glpi_group.add_argument(
        "--glpi-mode",
        choices=["rest", "inventory"],
        default="rest",
        help=(
            "Mode d'injection GLPI : "
            "'rest' = API REST GLPI, add-only garanti, --app-token et --user-token requis (défaut) ; "
            "'inventory' = plugin GLPI Inventory, sans token mais remplace les logiciels dynamiques"
        ),
    )
    glpi_group.add_argument(
        "--app-token",
        metavar="TOKEN",
        help="Jeton d'application GLPI (Configuration > Générale > API)",
    )
    glpi_group.add_argument(
        "--user-token",
        metavar="TOKEN",
        help="Jeton API utilisateur GLPI (visible dans le profil utilisateur)",
    )
    glpi_group.add_argument(
        "--computer-name",
        metavar="NOM",
        help="Nom exact du poste dans GLPI (défaut : nom de la machine courante)",
    )
    glpi_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Simule l'envoi GLPI sans rien écrire (requiert --glpi-url)",
    )
    glpi_group.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Désactive la vérification du certificat SSL GLPI (non recommandé en production)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    home     = Path.home()
    os_name  = _os_name()
    user     = _current_user()
    computer = _computer_name()
    now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    context: dict[str, str] = {"now": now, "computer": computer, "user": user, "os": os_name}

    # ── Bannière ──────────────────────────────────────────────────────────────
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   INVENTAIRE DES EXTENSIONS NAVIGATEURS & ADD-INS           ║")
    print(f"║   OS : {os_name:<12}  |  Utilisateur : {user:<19}║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    all_results: list[ExtensionEntry] = []

    # ── 1. Navigateurs Chromium ───────────────────────────────────────────────
    print("[1/5] Navigateurs Chromium (Chrome, Chromium, Brave, Edge)...")
    for name, path in _build_chromium_paths(home).items():
        all_results.extend(
            collect_chromium_extensions(name, path, context)
        )

    # ── 2. Firefox ────────────────────────────────────────────────────────────
    print("[2/5] Mozilla Firefox...")
    all_results.extend(
        collect_gecko_extensions(
            "Firefox", _build_firefox_path(home), context, args.include_internal
        )
    )

    # ── 3. Safari ─────────────────────────────────────────────────────────────
    print("[3/5] Apple Safari...")
    all_results.extend(collect_safari_extensions(context))

    # ── 4. Thunderbird ────────────────────────────────────────────────────────
    print("[4/5] Mozilla Thunderbird...")
    all_results.extend(
        collect_gecko_extensions(
            "Thunderbird", _build_thunderbird_path(home), context, args.include_internal
        )
    )

    # ── 5. Office ─────────────────────────────────────────────────────────────
    print("[5/5] Microsoft Office Add-ins...")
    match sys.platform:
        case "win32":
            all_results.extend(collect_office_addins_windows(context))
        case "darwin":
            all_results.extend(collect_office_addins_macos(context))
        case _:
            print("    [Office] Non disponible sur Linux (Office natif absent).")

    # ── Résumé ────────────────────────────────────────────────────────────────
    print()
    print("┌────────────────────────────────────────────────────────────────┐")
    print("│  SOURCE                                    │  NOMBRE           │")
    print("├────────────────────────────────────────────────────────────────┤")
    counts = Counter(r.source for r in all_results)
    for source, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"│  {source:<42}│  {count:<17}│")
    print("├────────────────────────────────────────────────────────────────┤")
    print(f"│  TOTAL{'':37}│  {len(all_results):<17}│")
    print("└────────────────────────────────────────────────────────────────┘")
    print()

    # ── Export ────────────────────────────────────────────────────────────────
    if not all_results:
        print("Aucune extension ou add-in trouvé.")
    else:
        fmt = args.format.lower()

        # Exports fichier désactivés — les données sont envoyées directement dans GLPI
        # base = Path(args.output)
        # if fmt in ("csv", "all"):
        #     export_csv(all_results, base.with_suffix(".csv"))
        # if fmt in ("json", "all"):
        #     export_json(all_results, base.with_suffix(".json"))

        if fmt in ("console", "all"):
            print_console(all_results)

    print("\nInventaire terminé.")

    # ── Envoi vers GLPI (si --glpi-url fourni) ────────────────────────────────
    if args.glpi_url:
        target_computer = args.computer_name or computer
        if not all_results:
            print("[GLPI] Aucune donnée à envoyer.")
        elif args.glpi_mode == "inventory":
            # ── Mode plugin GLPI Inventory (aucun token requis) ───────────────
            push_via_glpi_inventory_plugin(
                results=all_results,
                glpi_url=args.glpi_url,
                computer_name=target_computer,
                dry_run=args.dry_run,
                verify_ssl=not args.no_verify_ssl,
            )
        else:
            # ── Mode API REST GLPI ────────────────────────────────────────────
            missing = [
                n for n, v in (
                    ("--app-token",  args.app_token),
                    ("--user-token", args.user_token),
                )
                if not v
            ]
            if missing:
                print(
                    f"[GLPI REST] Paramètres manquants pour le mode 'rest' : "
                    f"{', '.join(missing)}"
                )
            else:
                push_to_glpi(
                    results=all_results,
                    glpi_url=args.glpi_url,
                    app_token=args.app_token,
                    user_token=args.user_token,
                    computer_name=target_computer,
                    dry_run=args.dry_run,
                    verify_ssl=not args.no_verify_ssl,
                )


if __name__ == "__main__":
    main()
