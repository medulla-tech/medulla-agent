# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Scheduled plugin to sync packages from Medulla Store API.

This plugin periodically checks for new packages from the Kestra API
and downloads them to the local Medulla server based on subscriptions.

Configuration file: scheduling_store_sync.ini
Also reads: /etc/mmc/plugins/store.ini(.local) for client_uuid and subscriptions
"""

import configparser
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import traceback
from datetime import datetime

try:
    import urllib.request
    import urllib.error
except ImportError:
    import urllib2 as urllib

logger = logging.getLogger()

plugin = { "VERSION": "2.0","NAME": "scheduling_store_sync","TYPE": "relayserver","SCHEDULED": True }

# Default: every 5 hours (matches Kestra version check interval)
SCHEDULE = {"schedule": "0 */5 * * *", "nb": -1}


def schedule_main(objectxmpp):
    """
    Main scheduled function - sync packages from Kestra API based on subscriptions
    """
    date = datetime.now()
    logger.info(f"=== {plugin['NAME']} started at {date} ===")

    # Initialize config on first run
    num_call = getattr(objectxmpp, f"num_call_{plugin['NAME']}", 0)
    if num_call == 0:
        read_config_plugin(objectxmpp)

    objectxmpp.__dict__[f"num_call_{plugin['NAME']}"] = num_call + 1

    # Check if properly configured
    config = getattr(objectxmpp, 'store_sync_config', None)
    if not config:
        logger.warning("Store sync not configured, skipping")
        return

    if not config.get('enabled', False):
        logger.debug("Store sync disabled in config")
        return

    try:
        # Sync packages based on subscriptions
        result = sync_packages(config)

        if result['success']:
            msg = f"Sync completed: {result['synced']} synced"
            if result.get('removed', 0) > 0:
                msg += f", {result['removed']} removed"
            msg += f" (subscribed to {result.get('total_subscribed', 0)} packages)"
            logger.info(msg)
        else:
            logger.error(f"Sync failed: {result.get('error', 'Unknown error')}")
            if result.get('errors'):
                for err in result['errors']:
                    logger.error(f"  - {err}")

    except Exception as e:
        logger.error(f"Error in store sync: {e}")
        logger.debug(traceback.format_exc())


def read_config_plugin(objectxmpp):
    """
    Read plugin configuration from INI file (with .local override support)
    Also reads MMC store.ini for client_uuid and database settings
    """
    # Find config directory
    try:
        from lib.agentconffile import directoryconffile
        confdir = directoryconffile()
    except:
        confdir = "/etc/pulse-xmpp-agent"

    configfile = os.path.join(confdir, f"{plugin['NAME']}.ini")
    configfile_local = os.path.join(confdir, f"{plugin['NAME']}.ini.local")

    config = {
        'enabled': False,
        'api_url': '',
        'api_token': '',
        'packages_path': '/var/lib/pulse2/packages/sharing/global',
        'generate_script': '/usr/sbin/pulse2-generation_package.py',
        'skip_ssl_verify': False,
        # From MMC store.ini
        'client_uuid': '',
        'store_db_host': 'localhost',
        'store_db_port': '3306',
        'store_db_name': 'store',
        'store_db_user': 'mmc',
        'store_db_pass': 'mmc',
        # From MMC pkgs.ini (for regeneration)
        'pkgs_db_host': 'localhost',
        'pkgs_db_port': '3306',
        'pkgs_db_user': 'mmc',
        'pkgs_db_pass': 'mmc',
    }

    # Read scheduler plugin config
    config_files = [configfile]
    if os.path.isfile(configfile_local):
        config_files.append(configfile_local)

    if os.path.isfile(configfile):
        try:
            parser = configparser.ConfigParser()
            parser.read(config_files)

            if parser.has_section('store_sync'):
                config['enabled'] = parser.getboolean('store_sync', 'enabled', fallback=False)
                config['api_url'] = parser.get('store_sync', 'api_url', fallback='')
                config['api_token'] = parser.get('store_sync', 'api_token', fallback='')
                config['packages_path'] = parser.get('store_sync', 'packages_path',
                                                      fallback='/var/lib/pulse2/packages/sharing/global')
                config['generate_script'] = parser.get('store_sync', 'generate_script',
                                                        fallback='/usr/sbin/pulse2-generation_package.py')
                config['skip_ssl_verify'] = parser.getboolean('store_sync', 'skip_ssl_verify', fallback=False)

            logger.info(f"Store sync config loaded: enabled={config['enabled']}, api_url={config['api_url']}")
        except Exception as e:
            logger.error(f"Error reading scheduler config: {e}")
    else:
        logger.warning(f"Config file not found: {configfile}")

    # Read MMC store.ini for client_uuid and database settings
    mmc_store_ini = '/etc/mmc/plugins/store.ini'
    mmc_store_ini_local = '/etc/mmc/plugins/store.ini.local'
    if os.path.isfile(mmc_store_ini):
        try:
            mmc_parser = configparser.ConfigParser()
            mmc_files = [mmc_store_ini]
            if os.path.isfile(mmc_store_ini_local):
                mmc_files.append(mmc_store_ini_local)
            mmc_parser.read(mmc_files)

            if mmc_parser.has_option('client', 'uuid'):
                config['client_uuid'] = mmc_parser.get('client', 'uuid', fallback='')

            if mmc_parser.has_section('database'):
                config['store_db_host'] = mmc_parser.get('database', 'dbhost', fallback='localhost')
                config['store_db_port'] = mmc_parser.get('database', 'dbport', fallback='3306')
                config['store_db_name'] = mmc_parser.get('database', 'dbname', fallback='store')
                config['store_db_user'] = mmc_parser.get('database', 'dbuser', fallback='mmc')
                config['store_db_pass'] = mmc_parser.get('database', 'dbpasswd', fallback='mmc')

            logger.info(f"MMC store config loaded: client_uuid={config['client_uuid']}")
        except Exception as e:
            logger.error(f"Error reading MMC store config: {e}")

    # Read MMC pkgs.ini for package regeneration database settings
    mmc_pkgs_ini = '/etc/mmc/plugins/pkgs.ini'
    mmc_pkgs_ini_local = '/etc/mmc/plugins/pkgs.ini.local'
    if os.path.isfile(mmc_pkgs_ini):
        try:
            pkgs_parser = configparser.ConfigParser()
            pkgs_files = [mmc_pkgs_ini]
            if os.path.isfile(mmc_pkgs_ini_local):
                pkgs_files.append(mmc_pkgs_ini_local)
            pkgs_parser.read(pkgs_files)

            if pkgs_parser.has_section('database'):
                config['pkgs_db_host'] = pkgs_parser.get('database', 'dbhost', fallback='localhost')
                config['pkgs_db_port'] = pkgs_parser.get('database', 'dbport', fallback='3306')
                config['pkgs_db_user'] = pkgs_parser.get('database', 'dbuser', fallback='mmc')
                config['pkgs_db_pass'] = pkgs_parser.get('database', 'dbpasswd', fallback='mmc')
        except Exception as e:
            logger.error(f"Error reading MMC pkgs config: {e}")

    objectxmpp.store_sync_config = config


def sync_packages(config):
    """
    Sync packages from Kestra API based on subscriptions.

    Args:
        config: dict with api_url, api_token, packages_path, client_uuid, db settings, etc.

    Returns:
        dict with success, synced count, removed count, errors
    """
    api_url = config['api_url'].rstrip('/')
    api_token = config['api_token']
    packages_path = config['packages_path']
    client_uuid = config.get('client_uuid', '')

    if not api_url or not api_token:
        return {'success': False, 'error': 'API URL or token not configured'}

    if not client_uuid:
        return {'success': False, 'error': 'Client UUID not configured in store.ini'}

    # Get subscribed package UUIDs from local database
    try:
        subscribed_packages = get_subscribed_packages(config)
    except Exception as e:
        return {'success': False, 'error': f'Failed to get subscriptions: {e}'}

    if not subscribed_packages:
        logger.info("No subscriptions found, cleaning up all packages")
        # Still need to cleanup any existing packages
        subscribed_uuids = set()
    else:
        subscribed_uuids = {pkg['package_uuid'] for pkg in subscribed_packages if pkg.get('package_uuid')}
        logger.info(f"Found {len(subscribed_uuids)} subscribed packages")

    # Fetch available packages from API
    try:
        available_packages = fetch_packages_list(api_url, api_token, config.get('skip_ssl_verify', False))
    except Exception as e:
        return {'success': False, 'error': f'Failed to fetch packages: {e}'}

    # Build lookup map: uuid -> package info
    available_map = {pkg['uuid']: pkg for pkg in available_packages}

    synced = 0
    errors = []

    # Sync each subscribed package
    for pkg_info in subscribed_packages:
        uuid = pkg_info.get('package_uuid')
        software_name = pkg_info.get('software_name', 'unknown')

        if not uuid:
            continue

        if uuid not in available_map:
            logger.warning(f"Package {uuid} ({software_name}) not available on Kestra API")
            continue

        remote_pkg = available_map[uuid]
        local_path = os.path.join(packages_path, uuid)

        try:
            result = download_package(api_url, api_token, remote_pkg, local_path,
                                       config.get('skip_ssl_verify', False))
            if result['success']:
                # Verify package files exist on disk before marking as deployed
                conf_exists = os.path.exists(os.path.join(local_path, 'conf.json'))
                xmppdeploy_exists = os.path.exists(os.path.join(local_path, 'xmppdeploy.json'))

                if conf_exists and xmppdeploy_exists:
                    # Update deployed_at in database
                    update_deployed_at(config, uuid)
                    synced += 1
                    logger.debug(f"Synced {software_name} ({uuid})")
                else:
                    errors.append(f"{software_name}: Package files missing after download")
                    logger.error(f"Package {uuid} files missing: conf.json={conf_exists}, xmppdeploy.json={xmppdeploy_exists}")
            else:
                errors.append(f"{software_name}: {result.get('error')}")
        except Exception as e:
            errors.append(f"{software_name}: {e}")

    # Cleanup unsubscribed packages
    removed = 0
    removed_packages = []
    try:
        removed, removed_packages = cleanup_unsubscribed_packages(packages_path, subscribed_uuids)
        if removed > 0:
            logger.info(f"Cleaned up {removed} unsubscribed packages: {removed_packages}")
            # Clear deployed_at for each removed package
            for pkg_uuid in removed_packages:
                clear_deployed_at(config, pkg_uuid)
    except Exception as e:
        logger.error(f"Failed to cleanup packages: {e}")
        errors.append(f"Cleanup failed: {e}")

    # Regenerate package database if we synced or removed anything
    if synced > 0 or removed > 0:
        try:
            regenerate_packages(config)
            logger.info("Package database regenerated successfully")
        except Exception as e:
            logger.error(f"Failed to regenerate packages: {e}")
            errors.append(f"Regeneration: {e}")

    return {
        'success': len(errors) == 0,
        'synced': synced,
        'removed': removed,
        'removed_packages': removed_packages if removed_packages else None,
        'total_subscribed': len(subscribed_packages),
        'errors': errors if errors else None
    }


def get_subscribed_packages(config):
    """
    Get subscribed package UUIDs from the local store database.

    Returns:
        list of dicts with package_uuid and software_name
    """
    try:
        import MySQLdb
    except ImportError:
        import pymysql as MySQLdb

    client_uuid = config['client_uuid']

    conn = MySQLdb.connect(
        host=config['store_db_host'],
        port=int(config['store_db_port']),
        user=config['store_db_user'],
        passwd=config['store_db_pass'],
        db=config['store_db_name']
    )

    try:
        cursor = conn.cursor()
        query = """
            SELECT sd.package_uuid, s.name as software_name
            FROM subscriptions sub
            JOIN clients c ON sub.client_id = c.id
            JOIN software s ON sub.software_id = s.id
            LEFT JOIN software_downloads sd ON s.id = sd.software_id
            WHERE c.uuid = %s
              AND sd.package_uuid IS NOT NULL
              AND sd.package_built_at IS NOT NULL
        """
        cursor.execute(query, (client_uuid,))
        rows = cursor.fetchall()

        return [{'package_uuid': row[0], 'software_name': row[1]} for row in rows]
    finally:
        conn.close()


def fetch_packages_list(api_url, api_token, skip_ssl=False):
    """
    Fetch packages.json from Kestra API
    """
    url = f"{api_url}/api/packages"

    req = urllib.request.Request(
        url,
        headers={
            'Authorization': f'Bearer {api_token}',
            'Accept': 'application/json'
        },
        method='GET'
    )

    ssl_context = None
    if skip_ssl:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    with urllib.request.urlopen(req, timeout=30, context=ssl_context) as response:
        data = json.loads(response.read().decode('utf-8'))
        return data.get('packages', [])


def download_package(api_url, api_token, remote_pkg, local_path, skip_ssl=False):
    """
    Download all files for a package from Kestra API
    """
    os.makedirs(local_path, exist_ok=True)

    ssl_context = None
    if skip_ssl:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    path = remote_pkg.get('path', '')
    files = remote_pkg.get('files', [])

    for filename in files:
        file_url = f"{api_url}/files/{path}/{filename}"
        local_file = os.path.join(local_path, filename)

        # Skip if file exists (except metadata files which should always be updated)
        if os.path.exists(local_file) and os.path.getsize(local_file) > 0:
            if filename not in ('conf.json', 'xmppdeploy.json'):
                continue

        req = urllib.request.Request(
            file_url,
            headers={'Authorization': f'Bearer {api_token}'},
            method='GET'
        )

        try:
            with urllib.request.urlopen(req, timeout=300, context=ssl_context) as response:
                with open(local_file, 'wb') as f:
                    shutil.copyfileobj(response, f)
        except urllib.error.HTTPError as e:
            return {'success': False, 'error': f'HTTP {e.code} for {filename}'}

    return {'success': True}


def cleanup_unsubscribed_packages(packages_path, subscribed_uuids):
    """
    Remove packages that are not in the subscribed list.

    Args:
        packages_path: base packages directory (e.g., /var/lib/pulse2/packages/sharing/global)
        subscribed_uuids: set of package UUIDs we're subscribed to

    Returns:
        tuple: (count of removed packages, list of removed UUIDs)
    """
    if not os.path.isdir(packages_path):
        return 0, []

    # UUID pattern
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

    removed = 0
    removed_packages = []

    for entry in os.listdir(packages_path):
        entry_path = os.path.join(packages_path, entry)

        # Only process UUID-named directories
        if not os.path.isdir(entry_path):
            continue
        if not uuid_pattern.match(entry):
            continue

        # Skip if subscribed
        if entry in subscribed_uuids:
            continue

        # Remove unsubscribed package
        try:
            shutil.rmtree(entry_path)
            removed += 1
            removed_packages.append(entry)
            logger.info(f"Removed unsubscribed package: {entry}")
            # Note: clear_deployed_at is called separately after this function returns
        except Exception as e:
            logger.error(f"Failed to remove package {entry}: {e}")

    return removed, removed_packages


def regenerate_packages(config):
    """
    Run pulse2-generation_package.py to register packages in Medulla
    """
    script = config['generate_script']

    if not os.path.exists(script):
        raise Exception(f"Script not found: {script}")

    # Use pkgs database credentials
    cmd = [
        script, '-r', '-l', '-g',
        '-u', config['pkgs_db_user'],
        '-p', config['pkgs_db_pass'],
        '-H', config['pkgs_db_host'],
        '-P', config['pkgs_db_port']
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300
    )

    if result.returncode != 0:
        raise Exception(f"Script failed: {result.stderr}")


def update_deployed_at(config, package_uuid):
    """
    Update deployed_at timestamp for a package after successful sync.

    Args:
        config: dict with database settings
        package_uuid: UUID of the package that was deployed
    """
    try:
        try:
            import MySQLdb
        except ImportError:
            import pymysql as MySQLdb

        conn = MySQLdb.connect(
            host=config['store_db_host'],
            port=int(config['store_db_port']),
            user=config['store_db_user'],
            passwd=config['store_db_pass'],
            db=config['store_db_name']
        )

        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE software_downloads SET deployed_at = NOW() WHERE package_uuid = %s",
                (package_uuid,)
            )
            conn.commit()
            logger.debug(f"Updated deployed_at for {package_uuid}")
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Failed to update deployed_at for {package_uuid}: {e}")


def clear_deployed_at(config, package_uuid):
    """
    Clear deployed_at timestamp when a package is removed.

    Args:
        config: dict with database settings
        package_uuid: UUID of the package that was removed
    """
    try:
        try:
            import MySQLdb
        except ImportError:
            import pymysql as MySQLdb

        conn = MySQLdb.connect(
            host=config['store_db_host'],
            port=int(config['store_db_port']),
            user=config['store_db_user'],
            passwd=config['store_db_pass'],
            db=config['store_db_name']
        )

        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE software_downloads SET deployed_at = NULL WHERE package_uuid = %s",
                (package_uuid,)
            )
            conn.commit()
            logger.debug(f"Cleared deployed_at for {package_uuid}")
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Failed to clear deployed_at for {package_uuid}: {e}")
