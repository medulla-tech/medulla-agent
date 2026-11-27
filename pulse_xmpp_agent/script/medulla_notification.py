#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Notification window shown to the user during a deployment.

The answer is given by the exit code and written on the standard output:

    0   YES       the user clicked the "yes" button
    1   NO        the user clicked the "no" button
    2   TIMEOUT   nobody answered within the delay

Any failure exits with another code and a message on the standard error:

    10  unexpected error
    11  PyQt6 cannot be loaded
    12  Qt gave up, most often because the display cannot be opened
    13  invalid command line, or no message to display
    14  the window was closed without an answer
"""

import sys
import os
import re
import signal
import base64
import ctypes
import importlib.util
import traceback
from optparse import OptionParser

EXIT_YES = 0
EXIT_NO = 1
EXIT_TIMEOUT = 2
EXIT_ERROR = 10
EXIT_PYQT_MISSING = 11
EXIT_QT_FATAL = 12
EXIT_BAD_COMMAND_LINE = 13
EXIT_NO_ANSWER = 14


def fail(code, message):
    """
    Leave at once with an error code, also from inside a Qt callback.
    """
    print(message, file=sys.stderr, flush=True)
    os._exit(code)


try:
    from PyQt6.QtCore import (
        QDir,
        QLockFile,
        Qt,
        QTimer,
        QtMsgType,
        qInstallMessageHandler,
    )
    from PyQt6.QtGui import QColor, QFont, QFontMetrics, QIcon, QPainter, QPixmap
    from PyQt6.QtWidgets import (
        QApplication,
        QBoxLayout,
        QFrame,
        QHBoxLayout,
        QLabel,
        QLayout,
        QPushButton,
        QScrollArea,
        QVBoxLayout,
        QWidget,
    )
except ImportError as import_error:
    fail(EXIT_PYQT_MISSING, f"PyQt6 cannot be loaded: {import_error}")


# Appearance of the window: a card without system border, a blue band
# holding the logo and the header, a white body, the buttons and the
# remaining time. No transparency, shadow or rounded corner on the window,
# to be drawn the same without compositor.

DEFAULT_TITLE = "Medulla"
BRAND = "Medulla"

BLUE = "#25607d"
BLUE_DARK = "#1b475d"
BLUE_HOVER = "#1f526b"
GREEN = "#8cb63c"
TEXT_COLOR = "#2f3a44"
MUTED_COLOR = "#6c7a86"
LINE_COLOR = "#e1e8ee"
SURFACE = "#ffffff"
TRACK = "#e8eff3"

STYLE_SHEET = f"""
#card {{ background: {SURFACE}; border: 1px solid {BLUE_DARK}; }}
#band {{ background: {BLUE}; }}
#brand {{ color: #b9d7e3; background: transparent; }}
#header {{ color: #ffffff; background: transparent; }}
#paragraph {{ color: {TEXT_COLOR}; background: transparent; }}
#divider {{ background: {LINE_COLOR}; border: none; }}
#countdown {{ color: {MUTED_COLOR}; background: transparent; }}
#message, QScrollArea {{ background: transparent; border: none; }}
QScrollBar:vertical {{ background: {TRACK}; width: 8px; margin: 0; border-radius: 4px; }}
QScrollBar::handle:vertical {{ background: #b9c6d1; border-radius: 4px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: #9bafbd; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QPushButton {{ border-radius: 4px; padding: 0 18px; }}
#yes {{ background: {BLUE}; color: #ffffff; border: 1px solid {BLUE}; }}
#yes:hover {{ background: {BLUE_HOVER}; border-color: {BLUE_HOVER}; }}
#yes:pressed {{ background: {BLUE_DARK}; border-color: {BLUE_DARK}; }}
#no {{ background: {SURFACE}; color: {BLUE}; border: 1px solid #b9c6d1; }}
#no:hover {{ background: {TRACK}; border-color: {BLUE}; }}
#no:pressed {{ background: #d0e4ed; }}
"""

# Sizes in pixels.
WINDOW_WIDTH = 460
BORDER = 1
SIDE_MARGIN = 20
CONTENT_WIDTH = WINDOW_WIDTH - 2 * BORDER - 2 * SIDE_MARGIN

BAND_VERTICAL_MARGIN = 12
LOGO_HEIGHT = 34
LOGO_SPACING = 15
BRAND_FONT_SIZE = 10
BRAND_LETTER_SPACING = 1.4
HEADER_FONT_SIZE = 17

BODY_TOP_MARGIN = 18
BODY_BOTTOM_MARGIN = 16
MESSAGE_FONT_SIZE = 14
PARAGRAPH_SPACING = 12
MESSAGE_MAX_HEIGHT = 320
SCROLL_BAR_ROOM = 16

FOOTER_BOTTOM_MARGIN = 14
FOOTER_SPACING = 12
COUNTDOWN_FONT_SIZE = 12
BUTTON_FONT_SIZE = 13
BUTTON_MIN_WIDTH = 96
BUTTON_HEIGHT = 34
BUTTON_HORIZONTAL_PADDING = 38
BUTTON_SPACING = 8
TIME_BAR_HEIGHT = 4

# Windows open at the same time on the machine: each one is shifted by
# CASCADE_STEP to the right and to the bottom of the previous one, up to
# CASCADE_PLACES windows. The next ones open at the center.
CASCADE_STEP = 40
CASCADE_PLACES = 4

# How far a pixel of the logo file may be from BLUE and still be background.
LOGO_BACKGROUND_TOLERANCE = 24

NO_EFFECT = "accepted and without effect, the window sets its own sizes"


class Options(OptionParser):
    def error(self, msg):
        fail(EXIT_BAD_COMMAND_LINE, f"Invalid command line: {msg}")


def parse_options():
    optp = Options()
    optp.add_option(
        "-Y",
        "--Ybutton",
        dest="Ybutton",
        default="",
        help="Texte button Yes",
    )
    optp.add_option(
        "-B",
        "--Sumittext",
        dest="Sumittext",
        default="",
        help="Texte Sumit text",
    )
    optp.add_option(
        "-b",
        "--SizeSumittext",
        type="int",
        dest="SizeSumittext",
        default=20,
        help=NO_EFFECT,
    )

    optp.add_option(
        "-N",
        "--Nbutton",
        dest="Nbutton",
        default="",
        help="Texte button Not",
    )

    optp.add_option(
        "-t",
        "--timeout",
        type="int",
        dest="notificationTimeout",
        default=60,
        help="timeout seconde",
    )

    optp.add_option(
        "-c",
        "--center_window",
        action="store_true",
        dest="centerfenetre",
        default=False,
        help="accepted and without effect, the window is always centered",
    )
    optp.add_option(
        "-T",
        "--titrebox",
        dest="titrebox",
        default="",
        help="Texte a afficher dans le titre de la boite de dialogue",
    )
    optp.add_option(
        "-M",
        "--Message",
        dest="textnotification",
        default="",
        help="Texte a afficher dans la boite de dialogue",
    )
    optp.add_option(
        "-S",
        "--sizenotification",
        dest="sizenotification",
        type="int",
        default=15,
        help=NO_EFFECT,
    )
    optp.add_option(
        "-s",
        "--sizetextbutton",
        dest="sizetextbutton",
        type="int",
        default=15,
        help=NO_EFFECT,
    )
    opts, _ = optp.parse_args()
    return opts


def decode_text(encoded):
    """
    Args:
        encoded (str): The text in base64, its line breaks written "\\n".

    Returns:
        str: The text to display.
    """
    return base64.b64decode(encoded).decode("utf-8").replace("\\n", "\n")


# Logo. It is not delivered with this script: it is taken from what is
# already installed on the machine.


def agent_logo():
    """
    Returns:
        str: The logo downloaded in the bin folder of the Medulla install
        (Windows), None when there is no such install folder.
    """
    try:
        from pulse_xmpp_agent.lib.agentconffile import medullaPath

        return os.path.join(medullaPath(), "bin", "medulla_logo.png")
    except (ImportError, TypeError):
        return None


def kiosk_logo():
    """
    Returns:
        str: The logo of the kiosk, None when the kiosk is not installed.
    """
    try:
        spec = importlib.util.find_spec("kiosk_interface")
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.submodule_search_locations:
        return None
    return os.path.join(
        list(spec.submodule_search_locations)[0], "datas", "medulla_logo.png"
    )


# The first source giving a readable picture is displayed, none gives a
# window without logo.
LOGO_SOURCES = (agent_logo, kiosk_logo)


def differs_from_background(image, x):
    background = QColor(BLUE)
    for y in range(image.height()):
        color = image.pixelColor(x, y)
        if (
            max(
                abs(color.red() - background.red()),
                abs(color.green() - background.green()),
                abs(color.blue() - background.blue()),
            )
            > LOGO_BACKGROUND_TOLERANCE
        ):
            return True
    return False


def brain_only(pixmap):
    """
    The logo of the kiosk is the brain followed by the word "medulla".
    Keep the first block of columns that is not background.
    """
    image = pixmap.toImage()
    start = None
    for x in range(image.width()):
        drawn = differs_from_background(image, x)
        if start is None and drawn:
            start = x
        elif start is not None and not drawn:
            return pixmap.copy(start, 0, x - start, image.height())
    return pixmap


def find_logo():
    """
    Returns:
        QPixmap: The brain of the Medulla logo, None when no source has it.
    """
    for source in LOGO_SOURCES:
        path = source()
        if path is None:
            continue
        pixmap = QPixmap(path)
        if not pixmap.isNull():
            return brain_only(pixmap)
    return None


# Windows groups the windows of the task bar by application, and takes
# this window for one of Python.
WINDOWS_APPLICATION_ID = "Medulla.Notifications.1.0"

# Desktop entry of the kiosk, installed with the agent: the Linux desktops
# take from it the icon of this window in their bar.
DESKTOP_ENTRY = "medulla-kiosk"


def declare_windows_application():
    """
    On Windows, declare this process as an application of its own, for its
    entry of the task bar to carry the icon of the window and not the one of
    Python. Nothing to do on the other systems.
    """
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            WINDOWS_APPLICATION_ID
        )
    except (OSError, AttributeError) as error:
        print(
            f"The application cannot be declared to Windows: {error}",
            file=sys.stderr,
        )


def take_place():
    """
    Returns:
        tuple: The rank of this window among the notification windows open
        on the machine, and the lock holding this rank as long as the
        process lives. The rank is 0, without lock, when it cannot be known.
    """
    for rank in range(CASCADE_PLACES):
        lock = QLockFile(
            os.path.join(QDir.tempPath(), f"medulla_notification_{rank}.lock")
        )
        lock.setStaleLockTime(0)
        if lock.tryLock(0):
            return rank, lock
        if lock.error() != QLockFile.LockError.LockFailedError:
            break
    return 0, None


def text_font(size, bold=False, letter_spacing=0.0):
    font = QFont()
    font.setPixelSize(size)
    if bold:
        font.setWeight(QFont.Weight.DemiBold)
    if letter_spacing:
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, letter_spacing)
    return font


def text_label(text, name, font, width):
    """
    Returns:
        QLabel: Plain text of the given width, as high as its wrapped lines.
    """
    label = QLabel(text)
    label.setObjectName(name)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setFont(font)
    label.setWordWrap(True)
    label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
    label.setFixedSize(width, label.heightForWidth(width))
    return label


def message_paragraphs(message, width):
    """
    The blocks of the message, split on its blank lines. Two blocks (the
    same text in two languages) are separated by a line, more are spaced.

    Returns:
        QWidget: The blocks, at the height of their text.
    """
    box = QWidget()
    box.setObjectName("message")
    layout = QVBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(PARAGRAPH_SPACING)
    paragraphs = [p for p in re.split(r"\n\s*\n", message.strip()) if p.strip()]
    height = 0
    for index, paragraph in enumerate(paragraphs):
        if index and len(paragraphs) == 2:
            divider = QFrame()
            divider.setObjectName("divider")
            divider.setFixedHeight(1)
            layout.addWidget(divider)
            height += 1 + PARAGRAPH_SPACING
        if index:
            height += PARAGRAPH_SPACING
        label = text_label(
            paragraph, "paragraph", text_font(MESSAGE_FONT_SIZE), width
        )
        layout.addWidget(label)
        height += label.height()
    box.setFixedSize(width, height)
    return box


def message_widget(message):
    """
    Returns:
        QWidget: The message at its own height, scrolled when it is higher
        than MESSAGE_MAX_HEIGHT.
    """
    box = message_paragraphs(message, CONTENT_WIDTH)
    if box.height() <= MESSAGE_MAX_HEIGHT:
        return box
    area = QScrollArea()
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
    area.viewport().setAutoFillBackground(False)
    area.setWidget(message_paragraphs(message, CONTENT_WIDTH - SCROLL_BAR_ROOM))
    area.setFixedSize(CONTENT_WIDTH, MESSAGE_MAX_HEIGHT)
    return area


class TimeBar(QWidget):
    """
    Bar that empties as the time runs out.
    """

    def __init__(self):
        super().__init__()
        self.ratio = 1.0
        self.setFixedHeight(TIME_BAR_HEIGHT)

    def set_ratio(self, ratio):
        self.ratio = ratio
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(TRACK))
        painter.fillRect(
            0, 0, round(self.width() * self.ratio), self.height(), QColor(GREEN)
        )


class NotificationWindow(QFrame):
    """
    The window. It cannot be closed: it leaves by a button or by the delay,
    and answer holds the exit code of what happened.
    """

    def __init__(self, opts, logo):
        super().__init__()
        self.answer = None
        self.delay = max(1, opts.notificationTimeout)
        self.remaining = self.delay

        self.setObjectName("card")
        self.setWindowTitle(opts.titrebox or DEFAULT_TITLE)
        self.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setStyleSheet(STYLE_SHEET)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetFixedSize)

        layout.addWidget(self.band(logo, decode_text(opts.Sumittext).strip()))

        body = QVBoxLayout()
        body.setContentsMargins(
            SIDE_MARGIN, BODY_TOP_MARGIN, SIDE_MARGIN, BODY_BOTTOM_MARGIN
        )
        body.addWidget(message_widget(decode_text(opts.textnotification)))
        layout.addLayout(body)

        self.countdown = QLabel()
        self.countdown.setObjectName("countdown")
        self.countdown.setFont(text_font(COUNTDOWN_FONT_SIZE))
        layout.addLayout(
            self.footer(
                [
                    (opts.Ybutton, "yes", self.answer_yes),
                    (opts.Nbutton, "no", self.answer_no),
                ]
            )
        )
        self.time_bar = TimeBar()
        layout.addWidget(self.time_bar)
        self.show_remaining_time()

        self.rank, self.place = take_place()
        self.place_on_screen()
        self.clock = QTimer(self)
        self.clock.timeout.connect(self.one_second_less)
        self.clock.start(1000)

    def closeEvent(self, event):
        event.ignore()

    def place_on_screen(self):
        """
        At the center of the screen, shifted by its rank and kept inside
        the screen.
        """
        self.adjustSize()
        screen = self.screen().availableGeometry()
        geometry = self.frameGeometry()
        geometry.moveCenter(screen.center())
        geometry.translate(self.rank * CASCADE_STEP, self.rank * CASCADE_STEP)
        geometry.moveRight(min(geometry.right(), screen.right()))
        geometry.moveBottom(min(geometry.bottom(), screen.bottom()))
        self.move(geometry.topLeft())

    def band(self, logo, header):
        """
        The logo, then the header under the name of the product. Without
        header, the name of the product takes its place.
        """
        band = QFrame()
        band.setObjectName("band")
        band.setFixedWidth(WINDOW_WIDTH - 2 * BORDER)
        layout = QHBoxLayout(band)
        layout.setContentsMargins(
            SIDE_MARGIN, BAND_VERTICAL_MARGIN, SIDE_MARGIN, BAND_VERTICAL_MARGIN
        )
        layout.setSpacing(LOGO_SPACING)
        text_width = CONTENT_WIDTH

        if logo is not None:
            ratio = self.devicePixelRatioF()
            logo = logo.scaledToHeight(
                round(LOGO_HEIGHT * ratio), Qt.TransformationMode.SmoothTransformation
            )
            logo.setDevicePixelRatio(ratio)
            label = QLabel()
            label.setPixmap(logo)
            layout.addWidget(label, 0, Qt.AlignmentFlag.AlignVCenter)
            text_width -= round(logo.width() / ratio) + LOGO_SPACING

        titles = QVBoxLayout()
        titles.setSpacing(1)
        titles.addStretch(1)
        if header:
            brand = QLabel(BRAND.upper())
            brand.setObjectName("brand")
            brand.setFont(
                text_font(BRAND_FONT_SIZE, bold=True, letter_spacing=BRAND_LETTER_SPACING)
            )
            titles.addWidget(brand)
        titles.addWidget(
            text_label(
                header or BRAND,
                "header",
                text_font(HEADER_FONT_SIZE, bold=True),
                text_width,
            )
        )
        titles.addStretch(1)
        layout.addLayout(titles, 1)
        return band

    def footer(self, buttons):
        """
        The remaining time, then the buttons, one above the other when their
        labels do not fit side by side.

        Args:
            buttons (list): The (label, name, callback) of each button, a
            button without label is not displayed.
        """
        layout = QHBoxLayout()
        layout.setContentsMargins(SIDE_MARGIN, 0, SIDE_MARGIN, FOOTER_BOTTOM_MARGIN)
        layout.setSpacing(FOOTER_SPACING)
        layout.addWidget(self.countdown, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addStretch(1)

        font = text_font(BUTTON_FONT_SIZE, bold=True)
        metrics = QFontMetrics(font)
        buttons = [button for button in buttons if button[0]]
        needed_width = BUTTON_SPACING * (len(buttons) - 1) + sum(
            max(
                BUTTON_MIN_WIDTH,
                metrics.horizontalAdvance(label) + BUTTON_HORIZONTAL_PADDING,
            )
            for label, _name, _callback in buttons
        )
        available_width = (
            CONTENT_WIDTH - metrics.horizontalAdvance("00:00") - FOOTER_SPACING
        )
        group = QBoxLayout(
            QBoxLayout.Direction.LeftToRight
            if needed_width <= available_width
            else QBoxLayout.Direction.TopToBottom
        )
        group.setSpacing(BUTTON_SPACING)
        for label, name, callback in buttons:
            button = QPushButton(label)
            button.setObjectName(name)
            button.setFont(font)
            button.setMinimumSize(BUTTON_MIN_WIDTH, BUTTON_HEIGHT)
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(callback)
            group.addWidget(button)
        layout.addLayout(group)
        return layout

    def show_remaining_time(self):
        self.countdown.setText(f"{self.remaining // 60}:{self.remaining % 60:02d}")
        self.time_bar.set_ratio(self.remaining / self.delay)

    def one_second_less(self):
        self.remaining -= 1
        if self.remaining <= 0:
            self.answer_timeout()
            return
        self.show_remaining_time()

    def leave(self, answer, output):
        self.answer = answer
        self.clock.stop()
        if self.place is not None:
            self.place.unlock()
        print(output)
        QApplication.instance().exit()

    def answer_yes(self):
        self.leave(EXIT_YES, "YES")

    def answer_no(self):
        self.leave(EXIT_NO, "NO")

    def answer_timeout(self):
        self.leave(EXIT_TIMEOUT, "TIMEOUT")


def on_python_error(error_type, error, error_traceback):
    fail(
        EXIT_ERROR,
        "".join(traceback.format_exception(error_type, error, error_traceback)),
    )


def on_qt_message(message_type, _context, message):
    if message_type == QtMsgType.QtFatalMsg:
        fail(EXIT_QT_FATAL, f"Qt gave up: {message}")
    print(message, file=sys.stderr)


def main():
    sys.excepthook = on_python_error
    qInstallMessageHandler(on_qt_message)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    opts = parse_options()
    if opts.textnotification == "":
        fail(EXIT_BAD_COMMAND_LINE, "No message to display (option -M).")

    application = QApplication(sys.argv[:1])
    application.setDesktopFileName(DESKTOP_ENTRY)
    logo = find_logo()
    if logo is not None:
        declare_windows_application()
        application.setWindowIcon(QIcon(logo))
    window = NotificationWindow(opts, logo)
    window.show()
    application.exec()
    if window.answer is None:
        fail(EXIT_NO_ANSWER, "The window was closed without an answer.")
    sys.exit(window.answer)


if __name__ == "__main__":
    main()
