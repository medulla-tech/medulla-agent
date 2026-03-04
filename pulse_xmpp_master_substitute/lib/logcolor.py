#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import threading
import time
from typing import Optional, Callable

import datetime

# now we patch Python code to add color support to logging.StreamHandler


def add_coloring_to_emit_windows(fn):
    # add methods we need to the class
    # def _out_handle(self):
    # import ctypes
    # return ctypes.windll.kernel32.GetStdHandle(self.STD_OUTPUT_HANDLE)
    # out_handle = property(_out_handle)

    def _set_color(self, code):
        import ctypes

        # Constants from the Windows API
        self.STD_OUTPUT_HANDLE = -11
        hdl = ctypes.windll.kernel32.GetStdHandle(self.STD_OUTPUT_HANDLE)
        ctypes.windll.kernel32.SetConsoleTextAttribute(hdl, code)

    setattr(logging.StreamHandler, "_set_color", _set_color)

    def new(*args):
        FOREGROUND_BLUE = 0x0001  # text color contains blue.
        FOREGROUND_GREEN = 0x0002  # text color contains green.
        FOREGROUND_RED = 0x0004  # text color contains red.
        FOREGROUND_INTENSITY = 0x0008  # text color is intensified.
        FOREGROUND_WHITE = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED
        # winbase.h
        # STD_INPUT_HANDLE = -10
        # STD_OUTPUT_HANDLE = -11
        # STD_ERROR_HANDLE = -12

        # wincon.h
        # FOREGROUND_BLACK     = 0x0000
        FOREGROUND_BLUE = 0x0001
        FOREGROUND_GREEN = 0x0002
        # FOREGROUND_CYAN      = 0x0003
        FOREGROUND_RED = 0x0004
        FOREGROUND_MAGENTA = 0x0005
        FOREGROUND_YELLOW = 0x0006
        # FOREGROUND_GREY      = 0x0007
        FOREGROUND_INTENSITY = 0x0008  # foreground color is intensified.

        # BACKGROUND_BLACK     = 0x0000
        # BACKGROUND_BLUE      = 0x0010
        # BACKGROUND_GREEN     = 0x0020
        # BACKGROUND_CYAN      = 0x0030
        # BACKGROUND_RED       = 0x0040
        # BACKGROUND_MAGENTA   = 0x0050
        BACKGROUND_YELLOW = 0x0060
        # BACKGROUND_GREY      = 0x0070
        BACKGROUND_INTENSITY = 0x0080  # background color is intensified.

        levelno = args[1].levelno
        if levelno >= 50:
            color = (
                BACKGROUND_YELLOW
                | FOREGROUND_RED
                | FOREGROUND_INTENSITY
                | BACKGROUND_INTENSITY
            )
        elif levelno >= 40:
            color = FOREGROUND_RED | FOREGROUND_INTENSITY
        elif levelno >= 30:
            color = FOREGROUND_YELLOW | FOREGROUND_INTENSITY
        elif levelno >= 20:
            color = FOREGROUND_GREEN
        elif levelno >= 10:
            color = FOREGROUND_MAGENTA
        else:
            color = FOREGROUND_WHITE
        args[0]._set_color(color)

        ret = fn(*args)
        args[0]._set_color(FOREGROUND_WHITE)
        return ret

    return new


def add_coloring_to_emit_ansi(fn):
    # add methods we need to the class
    def new(*args):
        levelno = args[1].levelno
        if levelno >= 50:
            color = "\x1b[31m"  # red
        elif levelno >= 40:
            color = "\x1b[31m"  # red
        elif levelno >= 30:
            color = "\x1b[33m"  # yellow
        elif levelno >= 20:
            color = "\x1b[32m"  # green
        elif levelno >= 10:
            color = "\x1b[35m"  # pink
        else:
            color = "\x1b[0m"  # normal
        args[1].msg = color + str(args[1].msg) + "\x1b[0m"  # normal
        # print "after"
        return fn(*args)

    return new


class XmppLogHandler(logging.Handler):
    def __init__(self, xmpp_send_func: Callable[[str], None]):
        super().__init__()
        self.xmpp_send_func = xmpp_send_func
        self._active = False
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        if not self._active:
            return

        # Formater le message avec le niveau de log
        msg = self.format(record)

        # Récupérer le niveau de log et la date
        log_level = record.levelname
        log_time = datetime.datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')

        # Construire le message complet avec la date après le niveau de log
        full_msg = f"[{log_level}] [{log_time}] {msg}"

        # Envoyer le message via XMPP
        self.xmpp_send_func(full_msg)

    def set_log_level(self, level: int) -> None:
        """Ajuste le niveau de log du handler."""
        self.setLevel(level)

    def activate_for_seconds(self, seconds: int = 180) -> None:
        """Active le handler pour une durée donnée (en secondes).
        Si seconds == -1, active indéfiniment.
        Si déjà actif, réinitialise le timer.
        """
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()

            self._active = True
            if seconds != -1:
                self._timer = threading.Timer(seconds, self.deactivate_handler)
                self._timer.start()

    def deactivate_handler(self) -> None:
        """Désactive immédiatement le handler."""
        with self._lock:
            self._active = False
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def __del__(self):
        self.deactivate_handler()

