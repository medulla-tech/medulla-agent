#!/usr/bin/python
# -*- coding:utf-8 -*-
# color boite   0067b3
# file /pulse2_update_notification.py
import sys
import signal
from optparse import OptionParser
if sys.version_info[0] < 3:
    import Tkinter as tk     ## Python 2.x
    from Tkinter import *
    import ttk
    import tkMessageBox
else:
    import tkinter as tk     ## Python 3.x


import subprocess

def simplecommand(cmd):
    p = subprocess.Popen(cmd,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    result = p.stdout.readlines()
    obj = {'code': p.wait()}
    obj['result'] = result
    return obj


class dialogboxnotification:
    def __init__(self,
                 textnotification ,
                 Ytextebutton="",
                 Ntextebutton="",
                 notificationTimeout=20,
                 centerfenetre=True,
                 sizenotification=15,
                 sizetextbutton=30,
                 titrebox="",
                 sumittext="",
                 sizeHeadertext=20):
        self.result = 1
        self.notificationTimeout=notificationTimeout
        self.Ytextebutton=Ytextebutton
        self.Ntextebutton=Ntextebutton
        self.textnotification=textnotification
        self.result=-1
        self.centerfenetre=centerfenetre
        self.root=None
        self.sizenotification=sizenotification
        self.sizetextbutton=sizetextbutton
        self.titrebox=titrebox
        self.sumittext=sumittext
        self.sizeHeadertext=sizeHeadertext
        # fen.iconbitmap("/home/laurent/Documents/icone_test_1.xpm")


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
        win.geometry(f'{width}x{height}+{x}+{y}')
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
        ## Create main window
        self.root = tk.Tk()

        self.root.geometry("720x250+0+0")
        self.root.configure(bg='#0067b3')

        if not self.titrebox:
            self.root.overrideredirect(TRUE)
        else:
            self.root.title(self.titrebox)
            # Image_Data = 'iVBORw0KGgoAAAANSUhEUgAAAQ='
            # self.root.iconbitmap(self.root.PhotoImage(data=Image_Data))

        if self.Ytextebutton or self.Ntextebutton:
            #button_frame1 = tk.Frame(self.root)
            button_frame = tk.Frame(self.root,bg='#0067b3')
            #button_frame.columnconfigure(10)
            xpadvaleur = 70 if self.Ytextebutton == 0 or self.Ntextebutton == 0 else 40
            button_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=xpadvaleur, pady=(10))
            #button_frame1.pack(fill=tk.X, side=tk.BOTTOM, padx=xpadvaleur, pady=(10))

# B1 = Tkinter.Button(top, text ="FLAT", relief=FLAT )
# B2 = Tkinter.Button(top, text ="RAISED", relief=RAISED )
# B3 = Tkinter.Button(top, text ="SUNKEN", relief=SUNKEN )
# B4 = Tkinter.Button(top, text ="GROOVE", relief=GROOVE )
# B5 = Tkinter.Button(top, text ="RIDGE", relief=RIDGE )

            if self.Ytextebutton:
                Yes_button = tk.Button(button_frame,
                                       text=self.Ytextebutton,
                                       height=2,
                                       width = 15,
                                       bg='#0067b3',
                                       highlightthickness = 2,
                                       highlightbackground = "white",
                                       highlightcolor= '#0067b3',
                                       relief = 'solid',
                                       fg='white',
                                       borderwidth = '0',
                                       font=("calibri",
                                             self.sizetextbutton,
                                             'bold',
                                             'underline'),
                                       command=self.ok,
                                       activebackground="#0076d7")

            if self.Ntextebutton:
                #No_button = tk.Button(button_frame, text=self.Ntextebutton,font=("Courier", self.sizetextbutton),command=self.no,
                        #activebackground="white")
                No_button  = tk.Button(button_frame,
                                       text=self.Ntextebutton,
                                       bg='#0067b3',
                                       height=2,
                                       width = 15,
                                       highlightthickness = 2,
                                       highlightbackground = "white",
                                       highlightcolor= '#0067b3',
                                       relief = 'solid',
                                       fg='white',
                                       borderwidth = '0',
                                       font=("calibri",
                                             self.sizetextbutton,
                                             'bold',
                                             'underline'),
                                       command=self.no,
                                       activebackground="#0076d7")
            if self.Ytextebutton == 0 or self.Ntextebutton == 0:
                button_frame.columnconfigure(0, weight=1)
            else:
                button_frame.columnconfigure(0, weight=6)
                button_frame.columnconfigure(6, weight=6)

            if self.Ytextebutton and self.Ntextebutton:
                Yes_button.grid(row=0, column=6)#, sticky=tk.W
                No_button.grid(row=0, column=7)#, sticky=tk.W
            elif self.Ytextebutton:
                Yes_button.pack(side=TOP, padx=10, pady=(10))
            elif self.Ntextebutton:
                No_button.pack(side=TOP, padx=10, pady=(10))

        #if self.sumittext != "":
        Label(text=self.sumittext.replace('\\n','\n'),
                padx=10,
                pady=(2),
                bg='#0067b3',
                fg='white',
                font=('Open Sans Soft Regular',self.sizeHeadertext, 'bold')).pack()

        Label(text=self.textnotification.replace('\\n','\n'),
              padx=10,
              pady=(2),
              bg='#0067b3',
              fg = 'white',
              font=("Open Sans Soft Regular",self.sizenotification)).pack()

        self.root.update_idletasks()
        ## Remove window decorations
        #self.root.overrideredirect(1)
        timeOut = int(self.notificationTimeout*1000) # Convert to ms from s
        ## Run appliction
        self.root.wm_attributes("-topmost", 1)
        self.root.after(timeOut,self.timeout)
        if self.centerfenetre:
            self.center(self.root)
        self.root.mainloop()

if __name__ == "__main__":
    # if sys.platform.startswith('win'):
        # re = simplecommand("query user")
        # print(re['result'])
        # if len(re['result']) == 1:
            # print("NO USER")
            # sys.exit(4)
    # Quit the process if we don't want to continue
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(-1))
    optp = OptionParser()
    optp.add_option(
        "-Y",
        "--Ytextebutton",
        dest="Ytextebutton",
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
        "--Ntextebutton",
        dest="Ntextebutton",
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
    if opts.textnotification=="" :
        sys.exit(-1)
    a=dialogboxnotification(opts.textnotification,
                            notificationTimeout=opts.notificationTimeout,
                            Ytextebutton=opts.Ytextebutton,
                            Ntextebutton=opts.Ntextebutton,
                            centerfenetre=opts.centerfenetre,
                            sizenotification=opts.sizenotification,
                            sizetextbutton=opts.sizetextbutton,
                            titrebox=opts.titrebox,
                            sumittext=opts.Sumittext,
                            sizeHeadertext=opts.SizeSumittext)
    a.showNotification()
    sys.exit(a.get_result())
