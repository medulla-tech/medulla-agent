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
        self.result = 1
        self.notificationTimeout = notificationTimeout
        self.Ybutton = Ybutton
        self.Nbutton = Nbutton
        self.textnotification = textnotification
        self.result = -1
        self.centerfenetre = centerfenetre
        self.root = None
        self.sizenotification = sizenotification
        self.sizetextbutton = sizetextbutton
        self.titrebox = titrebox
        self.submittext = submittext
        self.sizeHeadertext = sizeHeadertext

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

        self.root.geometry("720x250")
        self.root.configure(bg="#25607d")
        self.root.resizable(width=False, height=False)
        # Disable the Close Window Control Icon
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        self.root.attributes("-topmost", True)

        if not self.titrebox:
            self.root.title("Medulla Update Notifications")
        else:
            self.root.title(self.titrebox)

        if self.Ybutton or self.Nbutton:
            button_frame = tk.Frame(self.root, bg="#25607d")
            xpadvaleur = 70 if self.Ybutton == 0 or self.Nbutton == 0 else 40
            button_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=xpadvaleur, pady=(10))

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
                    borderwidth="0",
                    font=("calibri", self.sizetextbutton, "bold", "underline"),
                    command=self.ok,
                    activebackground="#0076d7",
                )

            if self.Nbutton:
                No_button = tk.Button(
                    button_frame,
                    text=self.Nbutton,
                    bg="#25607d",
                    height=2,
                    width=15,
                    highlightthickness=2,
                    highlightbackground="white",
                    highlightcolor="#25607d",
                    relief="solid",
                    fg="white",
                    borderwidth="0",
                    font=("calibri", self.sizetextbutton, "bold", "underline"),
                    command=self.no,
                    activebackground="#0076d7",
                )
            if self.Ybutton == 0 or self.Nbutton == 0:
                button_frame.columnconfigure(0, weight=1)
            else:
                button_frame.columnconfigure(0, weight=6)
                button_frame.columnconfigure(6, weight=6)

            if self.Ybutton and self.Nbutton:
                Yes_button.grid(row=0, column=0)  # , sticky=tk.W
                No_button.grid(row=0, column=6)  # , sticky=tk.W
            elif self.Ybutton:
                Yes_button.pack(side=tk.TOP, padx=10, pady=(10))
            elif self.Nbutton:
                No_button.pack(side=tk.TOP, padx=10, pady=(10))

        tk.Label(
            text=self.submittext.replace("\\n", "\n"),
            padx=10,
            pady=(2),
            bg="#25607d",
            fg="white",
            font=("Open Sans Soft Regular", self.sizeHeadertext, "bold"),
        ).pack()

        tk.Label(
            text=self.textnotification.replace("\\n", "\n"),
            padx=10,
            pady=(2),
            bg="#25607d",
            fg="white",
            font=("Open Sans Soft Regular", self.sizenotification),
            wraplength=400,
        ).pack()


        iconPath = os.path.join(medullaPath(), "bin", "medulla_logo.png")
        if os.path.exists(iconPath):
            try:
                medullaLogoLocation = Image.open(iconPath)
                medullaLogo = ImageTk.PhotoImage(medullaLogoLocation)
                Medullalabel = tk.Label(image=medullaLogo, bg="#25607d")
                Medullalabel.image = medullaLogo
                Medullalabel.place(x=15, y=12)
            except Exception as error_loading:
                print("Failed to load the icon.")
                print(f"We got the error \n: {error_loading}")
                pass

        self.root.update_idletasks()
        # Remove window decorations
        timeOut = int(self.notificationTimeout * 1000)  # Convert to ms from s
        # Run appliction
        self.root.wm_attributes("-topmost", 1)
        self.root.after(timeOut, self.timeout)
        if self.centerfenetre:
            self.center(self.root)
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
