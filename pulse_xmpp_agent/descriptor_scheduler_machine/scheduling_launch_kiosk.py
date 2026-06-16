# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2017-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin processes inventory from crontab descriptor time.
"""

import logging
import os
import sys
import platform
import psutil
import subprocess
from pulse_xmpp_agent.lib.utils import file_put_contents, simplecommand
from lib.agentconffile import directoryconffile
import configparser

logger = logging.getLogger()
plugin = {"VERSION": "1.6", "NAME": "scheduling_launch_kiosk", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/5 * * * *", "nb": -1}  # fmt: skip


def schedule_main(objectxmpp):
    logger.debug("###################################################")
    logger.debug("call %s ", plugin)
    logger.debug("###################################################")

    cleanup_old_kiosk()

    # Read the configuration on the first call
    num_compteur = getattr(objectxmpp, f'num_call_{plugin["NAME"]}')
    if num_compteur == 0:
        read_config_plugin_agent(objectxmpp)

    # Check if enable_kiosk is set to True in the configuration
    if not getattr(objectxmpp, "enable_kiosk", False):
        logger.debug("Kiosk is enabled in configuration.")
        return

    logger.debug("Kiosk is enabled in configuration.")

    system = platform.system().lower()
    if system == "windows":
        launch_kiosk_windows()
    elif system == "linux":
        launch_kiosk_linux()
    elif system == "darwin":
        launch_kiosk_macos()
    else:
        logger.debug("scheduling_launch_kiosk: unsupported platform '%s'.", system)


def launch_kiosk_windows():
    """Start the Kiosk on Windows by injecting it into the interactive session."""
    pid_file = "C:\\Program Files\\Medulla\\bin\\kiosk.pid"

    # Verify if Kiosk is already running using the PID file
    if os.path.exists(pid_file):
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        try:
            # Check if the process is still active
            p = psutil.Process(pid)
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                logger.debug("Kiosk is already running. PID: %d", pid)
                return
        except psutil.NoSuchProcess:
            logger.warning(
                f"Kiosk process with PID {pid} not found. Removing PID file."
            )
            os.remove(pid_file)

    session_id = get_session_id()
    if not session_id:
        logger.error("Cannot retrieve session ID. Kiosk will not be started.")
        return

    # Command to launch Kiosk if the process is not active
    command = f"""C:\\progra~1\\Medulla\\bin\\paexec.exe -accepteula -s -i {session_id} -d "C:\\Program Files\\Python3\\pythonw.exe" -m kiosk_interface"""

    logger.debug(f"Starting Kiosk. Command: {command}")
    process = subprocess.Popen(command, shell=True)

    # Create the PID file with the PID of the new process
    with open(pid_file, "w") as f:
        f.write(str(process.pid))
    logger.debug("Kiosk started successfully with PID: %d", process.pid)


def launch_kiosk_linux():
    """Start the Kiosk on Linux inside the active graphical user session.

    The agent runs as root (system service), but a Qt GUI must run inside the
    user's graphical session (DISPLAY/Wayland, XDG_RUNTIME_DIR, session D-Bus).
    This is the Linux equivalent of the Windows ``paexec -i <session>`` trick:
    we detect the active graphical session and launch the kiosk as that user
    with the relevant environment, using ``runuser`` (no password as root).
    """
    pid_file = "/tmp/kiosk.pid"

    # The kiosk writes its own PID to /tmp/kiosk.pid at startup (see
    # kiosk_interface/__main__.py), so we just rely on it here.
    if is_kiosk_running(pid_file):
        logger.debug("Kiosk is already running.")
        return

    session = get_linux_graphical_session()
    if not session:
        logger.warning("No active graphical session found. Kiosk will not be started.")
        return

    user = session["user"]
    uid = session["uid"]
    runtime_dir = "/run/user/%s" % uid

    # The most reliable way to attach a GUI to the user's graphical session is
    # to reuse the very environment its own processes run with (DISPLAY,
    # XAUTHORITY, WAYLAND_DISPLAY...). XAUTHORITY in particular is mandatory:
    # without it XWayland/X11 rejects the connection ("Authorization required").
    # This works for both X11 and Wayland (where Qt falls back to XWayland when
    # the native wayland plugin is absent).
    genv = get_user_graphical_env(uid)

    env_vars = {
        "XDG_RUNTIME_DIR": genv.get("XDG_RUNTIME_DIR", runtime_dir),
        "DBUS_SESSION_BUS_ADDRESS": genv.get(
            "DBUS_SESSION_BUS_ADDRESS", "unix:path=%s/bus" % runtime_dir
        ),
    }
    for key in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE"):
        if key in genv:
            env_vars[key] = genv[key]

    # Last-resort fallback if no display variable could be discovered.
    if "DISPLAY" not in env_vars and "WAYLAND_DISPLAY" not in env_vars:
        env_vars["DISPLAY"] = ":0"

    # Use the agent's own Python interpreter (the venv where the kiosk is
    # installed, e.g. /opt/medulla/bin/python3.11 on Linux), so the kiosk runs
    # with the same interpreter/site-packages as the agent - no hard-coded path.
    command = (
        ["runuser", "-u", user, "--", "env"]
        + ["%s=%s" % (k, v) for k, v in env_vars.items()]
        + [sys.executable, "-m", "kiosk_interface"]
    )

    logger.debug(
        "Starting Kiosk for user '%s' (uid=%s, env=%s).",
        user,
        uid,
        env_vars,
    )
    try:
        subprocess.Popen(
            command,
            close_fds=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.debug("Kiosk launch command sent for user '%s'.", user)
    except Exception as e:
        logger.error("Failed to start Kiosk: %s", e)


def launch_kiosk_macos():
    """Start the Kiosk on macOS inside the logged-in user's Aqua session.

    The agent runs as root (LaunchDaemon), but a Qt GUI must run inside the
    console user's graphical (Aqua/WindowServer) session. The macOS equivalent
    of the Windows ``paexec -i <session>`` / Linux ``runuser`` trick is
    ``launchctl asuser <uid> sudo -u <user> ...``: it places the process in the
    per-user GUI launchd domain (gui/<uid>), which is what grants access to
    WindowServer. No DISPLAY/XAUTHORITY juggling is needed (that is X11/Linux).
    """
    pid_file = "/tmp/kiosk.pid"

    # The kiosk writes its own PID to /tmp/kiosk.pid at startup (see
    # kiosk_interface/__main__.py), so we just rely on it here.
    if is_kiosk_running(pid_file):
        logger.debug("Kiosk is already running.")
        return

    user = get_macos_console_user()
    if not user:
        logger.warning("No active console user found. Kiosk will not be started.")
        return

    uid = _uid_of(user)
    if not uid:
        logger.warning("Cannot resolve uid of console user '%s'.", user)
        return

    # Run the kiosk with the agent's own interpreter (the venv where the kiosk
    # is installed, e.g. /opt/medulla/venv/bin/python3), so it shares the same
    # interpreter/site-packages as the agent - no hard-coded path.
    command = [
        "launchctl", "asuser", uid,
        "sudo", "-u", user,
        sys.executable, "-m", "kiosk_interface",
    ]

    logger.debug("Starting Kiosk for user '%s' (uid=%s).", user, uid)
    try:
        subprocess.Popen(
            command,
            close_fds=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.debug("Kiosk launch command sent for user '%s'.", user)
    except Exception as e:
        logger.error("Failed to start Kiosk: %s", e)


def get_macos_console_user():
    """Return the logged-in GUI (console) user on macOS, or None.

    Uses ``stat -f %Su /dev/console`` (same method as the macOS installer).
    Filters out root / loginwindow / setup users, which mean no real GUI user
    is logged in (login screen, fast-user-switch transition...).
    """
    try:
        res = simplecommand('stat -f "%Su" /dev/console')
        result = res.get("result", [])
        if not result:
            return None
        user = result[0].strip()
        if not user or user in ("root", "loginwindow", "_mbsetupuser"):
            return None
        return user
    except Exception as e:
        logger.debug("macOS console user detection failed: %s", e)
        return None


def is_kiosk_running(pid_file):
    """Return True if a live kiosk process is referenced by ``pid_file``.

    Stale PID files (process gone or zombie) are removed and treated as 'not
    running'.
    """
    if not os.path.exists(pid_file):
        return False
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        p = psutil.Process(pid)
        if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
            return True
    except (psutil.NoSuchProcess, ValueError, FileNotFoundError):
        pass
    # Stale PID file: clean it up.
    try:
        os.remove(pid_file)
        logger.debug("Removed stale PID file: %s", pid_file)
    except OSError:
        pass
    return False


def get_linux_graphical_session():
    """Detect the active graphical session on Linux.

    Returns a dict ``{user, uid, display, type}`` for the first active x11 or
    wayland session, or ``None`` if none is found. Tries ``loginctl`` first,
    then falls back to parsing ``who``.
    """
    # Preferred path: loginctl (systemd-logind).
    try:
        res = simplecommand("loginctl list-sessions --no-legend")
        for line in res.get("result", []):
            parts = line.split()
            if not parts:
                continue
            session_id = parts[0]
            props = _loginctl_session_props(session_id)
            if props.get("State") == "active" and props.get("Class") == "user" and props.get("Type") in (
                "x11",
                "wayland",
            ):
                user = props.get("Name")
                uid = props.get("User")
                if user and uid:
                    return {
                        "user": user,
                        "uid": uid,
                        "display": props.get("Display", ""),
                        "type": props.get("Type", ""),
                    }
    except Exception as e:
        logger.debug("loginctl session detection failed: %s", e)

    # Fallback: parse `who` output, looking for an X display in parentheses.
    try:
        res = simplecommand("who")
        for line in res.get("result", []):
            if "(:" not in line:
                continue
            cols = line.split()
            if not cols:
                continue
            user = cols[0]
            display = line[line.find("(") + 1 : line.find(")")]
            uid = _uid_of(user)
            if uid:
                return {
                    "user": user,
                    "uid": uid,
                    "display": display,
                    "type": "x11",
                }
    except Exception as e:
        logger.debug("who session detection failed: %s", e)

    return None


def _loginctl_session_props(session_id):
    """Return the loginctl properties of a session as a dict."""
    props = {}
    res = simplecommand(
        "loginctl show-session %s -p Name -p User -p State -p Type -p Display -p Class"
        % session_id
    )
    for line in res.get("result", []):
        if "=" in line:
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()
    return props


def get_user_graphical_env(uid):
    """Return the graphical environment of the user's session.

    Scans the processes owned by ``uid`` and reads ``/proc/<pid>/environ`` to
    pick up the graphical-session variables (DISPLAY, XAUTHORITY,
    WAYLAND_DISPLAY, XDG_RUNTIME_DIR, DBUS_SESSION_BUS_ADDRESS...). Returns the
    first candidate exposing both DISPLAY and XAUTHORITY (the usable X case),
    otherwise the richest candidate found, or an empty dict.
    """
    wanted = (
        "DISPLAY",
        "XAUTHORITY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_SESSION_TYPE",
    )
    try:
        uid = int(uid)
    except (TypeError, ValueError):
        return {}

    best = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        proc = "/proc/%s" % pid
        try:
            if os.stat(proc).st_uid != uid:
                continue
            with open(os.path.join(proc, "environ"), "rb") as f:
                raw = f.read()
        except (OSError, IOError):
            continue

        env = {}
        for chunk in raw.split(b"\x00"):
            if b"=" not in chunk:
                continue
            key, _, value = chunk.partition(b"=")
            try:
                env[key.decode()] = value.decode()
            except UnicodeDecodeError:
                continue

        candidate = {k: env[k] for k in wanted if k in env}
        # Best case: a process that has both a display and its X cookie.
        if "DISPLAY" in candidate and "XAUTHORITY" in candidate:
            return candidate
        if len(candidate) > len(best):
            best = candidate
    return best


def _uid_of(username):
    """Return the uid (as str) of a username, or None if unknown."""
    try:
        import pwd

        return str(pwd.getpwnam(username).pw_uid)
    except Exception:
        return None


def read_config_plugin_agent(objectxmpp):
    configfilename = os.path.join(directoryconffile(), f'{plugin["NAME"]}.ini')
    logger.debug(f"Reading configuration file: {configfilename}")

    # Create the config file if it does not exist
    if not os.path.isfile(configfilename):
        logger.warning(f"No configuration file found: {configfilename}")
        logger.warning("Automatically creating the missing configuration file.")
        file_put_contents(
            configfilename,
            "[scheduling_launch_kiosk]\n"
            "# Enable execution of kiosk\n"
            "# enable_kiosk = True\n",
        )

    # Read the configuration file
    Config = configparser.ConfigParser()
    Config.read(configfilename)

    # Set enable_kiosk based on the configuration file
    try:
        objectxmpp.enable_kiosk = Config.getboolean(
            "scheduling_launch_kiosk", "enable_kiosk"
        )
    except (configparser.NoOptionError, configparser.NoSectionError, ValueError):
        objectxmpp.enable_kiosk = (
            True  # Default to True if the setting is missing or invalid
        )
        logger.warning(
            "The 'enable_kiosk' option is missing or invalid. Defaulting to True."
        )


def get_session_id():
    try:
        re = simplecommand("query user")
        if len(re.get("result", [])) >= 2:
            userdata = [x.strip("> ") for x in re["result"][1].split(" ") if x != ""]
            user_id = userdata[2]
            logger.debug(f"Session ID: {user_id}")
            return user_id
        else:
            logger.warning("No active user session found.")
            return None
    except Exception as e:
        logger.error(f"Failed to retrieve session ID: {e}")
        return None


def cleanup_old_kiosk():
    """Terminate any old Kiosk process, remove old PID file, and delete old startup script."""
    old_pid_file = "C:\\Windows\\Temp\\kiosk.pid"
    startup_script = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\RunMedullaKiosk.bat"

    # Finish the Kiosk process if the PID file exists
    if os.path.exists(old_pid_file):
        try:
            with open(old_pid_file, "r") as f:
                pid = int(f.read().strip())
            psutil.Process(pid).terminate()
            logger.debug(f"Old Kiosk process with PID {pid} terminated.")
        except (psutil.NoSuchProcess, ValueError):
            logger.debug("No old Kiosk process found to terminate.")
        finally:
            os.remove(old_pid_file)
            logger.debug("old kiosk.pid file deleted.")

    # Remove the old starter script if there is
    if os.path.exists(startup_script):
        try:
            os.remove(startup_script)
            logger.debug(f"Old startup script '{startup_script}' successfully deleted.")
        except Exception as e:
            logger.error(f"Failed to delete old startup script '{startup_script}': {e}")
