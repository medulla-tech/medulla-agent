#!/usr/bin/python3
# -*- coding:utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import signal
from optparse import OptionParser
import os

import tkinter as tk
from PIL import Image, ImageTk

import subprocess

from pulse_xmpp_agent.lib.agentconffile import medullaPath


def simplecommand(cmd):
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    result = p.stdout.readlines()
    obj = {"code": p.wait()}
    obj["result"] = result
    return obj


class dialogboxnotification:
    def __init__(
        self,
        textnotification,
        Ybutton="",
        Nbutton="",
        notificationTimeout=20,
        centerfenetre=True,
        sizenotification=15,
        sizetextbutton=30,
        titrebox="",
        submittext="",
        sizeHeadertext=20,
    ):

        # Define the maximum sizes for fonts
        MAX_SIZE_HEADER_TEXT = 20
        MAX_SIZE_NOTIFICATION = 15
        MAX_SIZE_TEXT_BUTTON = 20

        self.sizeHeadertext = min(sizeHeadertext, MAX_SIZE_HEADER_TEXT)
        self.sizenotification = min(sizenotification, MAX_SIZE_NOTIFICATION)
        self.sizetextbutton = min(sizetextbutton, MAX_SIZE_TEXT_BUTTON)

        self.result = 1
        self.notificationTimeout = notificationTimeout
        self.Ybutton = Ybutton
        self.Nbutton = Nbutton
        self.textnotification = textnotification
        self.result = -1
        self.centerfenetre = centerfenetre
        self.root = None
        self.titrebox = titrebox
        self.submittext = submittext

    def center(self, win):
        """
        centers a tkinter window
        :param win: the main window or Toplevel window to center
        """
        win.update_idletasks()
        width = win.winfo_width()
        frm_width = win.winfo_rootx() - win.winfo_x()
        win_width = width + 2 * frm_width
        height = win.winfo_height()
        titlebar_height = win.winfo_rooty() - win.winfo_y()
        win_height = height + titlebar_height + frm_width
        x = win.winfo_screenwidth() // 2 - win_width // 2
        y = win.winfo_screenheight() // 2 - win_height // 2
        win.geometry(f"{width}x{height}+{x}+{y}")
        win.deiconify()

    def ok(self):
        self.result = 0
        print("YES")
        self.root.quit()

    def no(self):
        self.result = 1
        print("NO")
        self.root.quit()

    def timeout(self):
        print("TIMEOUT")
        self.result = 2
        self.root.destroy()

    def get_result(self):
        return self.result

    def text_box(self):
        pass

    def showNotification(self):
        # Create main window
        self.root = tk.Tk()

        self.root.configure(bg="#25607d")
        self.root.resizable(width=False, height=False)
        # Disable the Close Window Control Icon
        self.root.resizable(width=True, height=True) # Allow the window to be resized
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        self.root.attributes("-topmost", True)

        if not self.titrebox:
            self.root.title("Medulla Update Notifications")
        else:
            self.root.title(self.titrebox)

        # Main frame with two columns
        main_frame = tk.Frame(self.root, bg="#25607d")
        main_frame.pack(fill='both', expand=True)

        # Configure columns and rows
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=2)
        main_frame.rowconfigure(0, weight=1)

        # Frame for the image on the left, with padding
        image_frame = tk.Frame(main_frame, bg="#25607d")
        image_frame.grid(row=0, column=0, sticky="nsew", padx=(20, 10), pady=20)

        # Frame for right content, with padding
        content_frame = tk.Frame(main_frame, bg="#25607d")
        content_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 20), pady=20)

        image_frame.columnconfigure(0, weight=1)
        image_frame.rowconfigure(0, weight=1)

        # Load and display the image in Image_Frame
        iconPath = os.path.join(medullaPath(), "bin", "medulla_logo.png")
        if os.path.exists(iconPath):
            try:
                medullaLogoLocation = Image.open(iconPath)
                image_max_size = 200
                medullaLogoLocation.thumbnail((image_max_size, image_max_size), Image.LANCZOS)
                self.medullaLogo = ImageTk.PhotoImage(medullaLogoLocation)
                Medullalabel = tk.Label(image_frame, image=self.medullaLogo, bg="#25607d")
                Medullalabel.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')# Padding around the image
            except Exception as error_loading:
                print("Impossible to load the icon.")
                print(f"Erreur : \n{error_loading}")
        else:
            # If the image does not exist, leave the space empty
            Medullalabel = tk.Label(image_frame, bg="#25607d")
            Medullalabel.grid(row=0, column=0, sticky='nsew')

        # Configure content_frame to center content
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(0, weight=1)
        content_frame.rowconfigure(1, weight=1)
        content_frame.rowconfigure(2, weight=1)
        content_frame.rowconfigure(3, weight=1)
        content_frame.rowconfigure(4, weight=1)

        # Limit the width of the text so that it adapts to the framework
        text_wrap_length = 350

        submittext_label = tk.Label(
            content_frame,
            text=self.submittext.replace("\\n", "\n"),
            bg="#25607d",
            fg="white",
            font=("Open Sans Soft Regular", self.sizeHeadertext, "bold"),
            wraplength=text_wrap_length,
            justify='center',
        )
        submittext_label.grid(row=1, column=0, padx=10, pady=(10, 5), sticky='n')

        textnotification_label = tk.Label(
            content_frame,
            text=self.textnotification.replace("\\n", "\n"),
            bg="#25607d",
            fg="white",
            font=("Open Sans Soft Regular", self.sizenotification),
            wraplength=text_wrap_length,
            justify='center',
        )
        textnotification_label.grid(row=2, column=0, padx=10, pady=(0, 10), sticky='n')


        if self.Ybutton or self.Nbutton:
            button_frame = tk.Frame(content_frame, bg="#25607d")
            button_frame.grid(row=3, column=0, pady=10, sticky='n')

            if self.Ybutton:
                Yes_button = tk.Button(
                    button_frame,
                    text=self.Ybutton,
                    height=2,
                    width=15,
                    bg="#25607d",
                    highlightthickness=2,
                    highlightbackground="white",
                    highlightcolor="#25607d",
                    relief="solid",
                    fg="white",
                    borderwidth=0,
                    font=("calibri", self.sizetextbutton, "bold", "underline"),
                    command=self.ok,
                    activebackground="#0076d7",
                )
                Yes_button.pack(side=tk.LEFT, padx=10)

            if self.Nbutton:
                No_button = tk.Button(
                    button_frame,
                    text=self.Nbutton,
                    height=2,
                    width=15,
                    bg="#25607d",
                    highlightthickness=2,
                    highlightbackground="white",
                    highlightcolor="#25607d",
                    relief="solid",
                    fg="white",
                    borderwidth=0,
                    font=("calibri", self.sizetextbutton, "bold", "underline"),
                    command=self.no,
                    activebackground="#0076d7",
                )
                No_button.pack(side=tk.LEFT, padx=10)

        if self.centerfenetre:
            self.root.update_idletasks()
            self.center(self.root)

        # Configure the time before closing
        timeOut = int(self.notificationTimeout * 1000)
        self.root.after(timeOut, self.timeout)

        self.root.mainloop()

if __name__ == "__main__":
    # Quit the process if we don't want to continue
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(-1))
    optp = OptionParser()
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
        help="Texte Sumit text",
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
        help="la boite de dialogue est centre sur la page",
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
        help="size texte notification",
    )
    optp.add_option(
        "-s",
        "--sizetextbutton",
        dest="sizetextbutton",
        type="int",
        default=15,
        help="size texte notification",
    )
    opts, args = optp.parse_args()
    if opts.textnotification == "":
        sys.exit(-1)

    a = dialogboxnotification(
        opts.textnotification,
        notificationTimeout=opts.notificationTimeout,
        Ybutton=opts.Ybutton,
        Nbutton=opts.Nbutton,
        centerfenetre=opts.centerfenetre,
        sizenotification=opts.sizenotification,
        sizetextbutton=opts.sizetextbutton,
        titrebox=opts.titrebox,
        submittext=opts.Sumittext,
        sizeHeadertext=opts.SizeSumittext,
    )
    a.showNotification()
    sys.exit(a.get_result())
