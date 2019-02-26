# -*- coding: utf-8; -*-
#
# (c) 2016 siveo, http://www.siveo.net
#
# $Id$
#
# This file is part of Mandriva Management Console (MMC).
#
# MMC is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# MMC is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MMC.  If not, see <http://www.gnu.org/licenses/>.
#
#
"""
function for monitoring
"""
import os
import psutil
import datetime, time
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM

def secs2hours(secs):
    mm, ss = divmod(secs, 60)
    hh, mm = divmod(mm, 60)
    return "%d:%02d:%02d" % (hh, mm, ss)


def sensors_battery():
    result = "no battery is installed"
    if not hasattr(psutil, "sensors_battery"):
        return result
    batt = psutil.sensors_battery()
    if batt is None:
        return result
    result = "charge:     %s%%" % round(batt.percent, 2)
    if batt.power_plugged:
        va ="status:     %s" % (
            "charging" if batt.percent < 100 else "fully charged")
        vb ="plugged in: yes"
        return result + "\n" + va + "\n" + vb 
    else:
        va = "left:       %s" % secs2hours(batt.secsleft)
        vb = "status:     %s" % "discharging"
        vc = "plugged in: no"
        return result + "\n" + va + "\n" + vb + "\n" + vc


def winservices():
    """
    $ function winservices return string of List all Windows services installed.
    AeLookupSvc (Application Experience)
    status: stopped, start: manual, username: localSystem, pid: None
    binpath: C:\Windows\system32\svchost.exe -k netsvcs

    ALG (Application Layer Gateway Service)
    status: stopped, start: manual, username: NT AUTHORITY\LocalService, pid: None
    binpath: C:\Windows\System32\alg.exe

    APNMCP (Ask Update Service)
    status: running, start: automatic, username: LocalSystem, pid: 1108
    binpath: "C:\Program Files (x86)\AskPartnerNetwork\Toolbar\apnmcp.exe"

    AppIDSvc (Application Identity)
    status: stopped, start: manual, username: NT Authority\LocalService, pid: None
    binpath: C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation

    Appinfo (Application Information)
    status: stopped, start: manual, username: LocalSystem, pid: None
    binpath: C:\Windows\system32\svchost.exe -k netsvcs
    """
    result = ""
    if os.name != 'nt':
        return "platform not supported (Windows only)"
    for service in psutil.win_service_iter():
        info = service.as_dict()
        result = result + "\n%r (%r)\n" % (info['name'], info['display_name'])
        result = result + "status: %s, start: %s, username: %s, pid: %s\n" % (
            info['status'], info['start_type'], info['username'], info['pid'])
        result = result + "binpath: %s" % info['binpath']
    return result





PROC_STATUSES_RAW = {
    psutil.STATUS_RUNNING: "R",
    psutil.STATUS_SLEEPING: "S",
    psutil.STATUS_DISK_SLEEP: "D",
    psutil.STATUS_STOPPED: "T",
    psutil.STATUS_TRACING_STOP: "t",
    psutil.STATUS_ZOMBIE: "Z",
    psutil.STATUS_DEAD: "X",
    psutil.STATUS_WAKING: "WA",
    psutil.STATUS_IDLE: "I",
    psutil.STATUS_LOCKED: "L",
    psutil.STATUS_WAITING: "W",
}

if hasattr(psutil, 'STATUS_WAKE_KILL'):
    PROC_STATUSES_RAW[psutil.STATUS_WAKE_KILL] = "WK"

if hasattr(psutil, 'STATUS_SUSPENDED'):
    PROC_STATUSES_RAW[psutil.STATUS_SUSPENDED] = "V"


def clone_ps_aux():
    """
        function clone of 'ps -aux' on UNIX.
    """
    result = ""
    today_day = datetime.date.today()
    templ = "%-10s %5s %4s %4s %7s %7s %-13s %-5s %5s %7s  %s\n"
    attrs = ['pid', 'cpu_percent', 'memory_percent', 'name', 'cpu_times',
             'create_time', 'memory_info', 'status']
    if os.name == 'posix':
        attrs.append('uids')
        attrs.append('terminal')
    result = templ % ("USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY",
                   "STAT", "START", "TIME", "COMMAND")
    for p in psutil.process_iter():
        try:
            pinfo = p.as_dict(attrs, ad_value='')
        except psutil.NoSuchProcess:
            pass
        else:
            if pinfo['create_time']:
                ctime = datetime.datetime.fromtimestamp(pinfo['create_time'])
                if ctime.date() == today_day:
                    ctime = ctime.strftime("%H:%M")
                else:
                    ctime = ctime.strftime("%b%d")
            else:
                ctime = ''
            cputime = time.strftime("%M:%S",
                                    time.localtime(sum(pinfo['cpu_times'])))
            try:
                user = p.username()
            except KeyError:
                if os.name == 'posix':
                    if pinfo['uids']:
                        user = str(pinfo['uids'].real)
                    else:
                        user = ''
                else:
                    raise
            except psutil.Error:
                user = ''
            if os.name == 'nt' and '\\' in user:
                user = user.split('\\')[1]
            vms = pinfo['memory_info'] and \
                int(pinfo['memory_info'].vms / 1024) or '?'
            rss = pinfo['memory_info'] and \
                int(pinfo['memory_info'].rss / 1024) or '?'
            memp = pinfo['memory_percent'] and \
                round(pinfo['memory_percent'], 1) or '?'
            status = PROC_STATUSES_RAW.get(pinfo['status'], pinfo['status'])
            result = result  + templ % (
                user[:10],
                pinfo['pid'],
                pinfo['cpu_percent'],
                memp,
                vms,
                rss,
                pinfo.get('terminal', '') or '?',
                status,
                ctime,
                cputime,
                pinfo['name'].strip() or '?')
    result = result + "\n"     
    return result


def bytes2human(n):
    """

    Convert n bytes into a human readable string based on format.
    see: http://goo.gl/kTQMs
    see: http://code.activestate.com/recipes/578019

    >>> bytes2human(10000)
    '9.8 K'
    >>> bytes2human(100001221)
    '95.4 M'

    """
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return '%.2f%s' % (value, s)
    return '%.2fB' % (n)


def disk_usage():
    """
        List all mounted disk partitions a-la "df -h" command.

        $ python scripts/disk_usage.py
        Device               Total     Used     Free  Use %      Type  Mount
        /dev/sdb3            18.9G    14.7G     3.3G    77%      ext4  /
        /dev/sda6           345.9G    83.8G   244.5G    24%      ext4  /home
        /dev/sda1           296.0M    43.1M   252.9M    14%      vfat  /boot/efi
        /dev/sda2           600.0M   312.4M   287.6M    52%   fuseblk  /media/Recovery
    """
    templ = "%-17s %8s %8s %8s %5s%% %9s  %s\n"
    result = templ % ("Device", "Total", "Used", "Free", "Use ", "Type",
                   "Mount")
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt':
            if 'cdrom' in part.opts or part.fstype == '':
                # skip cd-rom drives with no disk in it; they may raise
                # ENOENT, pop-up a Windows GUI error for a non-ready
                # partition or just hang.
                continue
        usage = psutil.disk_usage(part.mountpoint)
        result = result + templ % (
            part.device,
            bytes2human(usage.total),
            bytes2human(usage.used),
            bytes2human(usage.free),
            int(usage.percent),
            part.fstype,
            part.mountpoint)
    return result

def sensors_fans():
    result = ""
    if not hasattr(psutil, "sensors_fans"):
        result = "sensors_fans platform not supported"
        return result
    fans = psutil.sensors_fans()
    if not fans:
        result = "no fans detected"
        return result
    for name, entries in fans.items():
        result = result + name + "\n"
        for entry in entries:
            result = result + "    %-20s %s RPM\n" % (entry.label or name, entry.current)
        result = result +"\n"
    return result


def mmemory():
    """
        A clone of 'free' cmdline utility.

        $ python scripts/free.py
                    total       used       free     shared    buffers      cache
        Mem:      10125520    8625996    1499524          0     349500    3307836
        Swap:            0          0          0
    """
    result = ""
    virt = psutil.virtual_memory()
    swap = psutil.swap_memory()
    templ = "%-7s %10s %10s %10s %10s %10s %10s\n"
    result = result + templ % ('', 'total', 'used', 'free', 'shared', 'buffers', 'cache')
    result = result + templ % (
        'Mem:',
        int(virt.total / 1024),
        int(virt.used / 1024),
        int(virt.free / 1024),
        int(getattr(virt, 'shared', 0) / 1024),
        int(getattr(virt, 'buffers', 0) / 1024),
        int(getattr(virt, 'cached', 0) / 1024))
    result = result + templ % (
        'Swap:', int(swap.total / 1024),
        int(swap.used / 1024),
        int(swap.free / 1024),
        '',
        '',
        '')
    return result



af_map = {
    socket.AF_INET: 'IPv4',
    socket.AF_INET6: 'IPv6',
    psutil.AF_LINK: 'MAC',
}

duplex_map = {
    psutil.NIC_DUPLEX_FULL: "full",
    psutil.NIC_DUPLEX_HALF: "half",
    psutil.NIC_DUPLEX_UNKNOWN: "?",
}


def ifconfig():
    """
        A clone of 'ifconfig' on UNIX.

        $ python scripts/ifconfig.py
        lo:
            stats          : speed=0MB, duplex=?, mtu=65536, up=yes
            incoming       : bytes=1.95M, pkts=22158, errs=0, drops=0
            outgoing       : bytes=1.95M, pkts=22158, errs=0, drops=0
            IPv4 address   : 127.0.0.1
                netmask   : 255.0.0.0
            IPv6 address   : ::1
                netmask   : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
            MAC  address   : 00:00:00:00:00:00

        docker0:
            stats          : speed=0MB, duplex=?, mtu=1500, up=yes
            incoming       : bytes=3.48M, pkts=65470, errs=0, drops=0
            outgoing       : bytes=164.06M, pkts=112993, errs=0, drops=0
            IPv4 address   : 172.17.0.1
                broadcast : 172.17.0.1
                netmask   : 255.255.0.0
            IPv6 address   : fe80::42:27ff:fe5e:799e%docker0
                netmask   : ffff:ffff:ffff:ffff::
            MAC  address   : 02:42:27:5e:79:9e
                broadcast : ff:ff:ff:ff:ff:ff

        wlp3s0:
            stats          : speed=0MB, duplex=?, mtu=1500, up=yes
            incoming       : bytes=7.04G, pkts=5637208, errs=0, drops=0
            outgoing       : bytes=372.01M, pkts=3200026, errs=0, drops=0
            IPv4 address   : 10.0.0.2
                broadcast : 10.255.255.255
                netmask   : 255.0.0.0
            IPv6 address   : fe80::ecb3:1584:5d17:937%wlp3s0
                netmask   : ffff:ffff:ffff:ffff::
            MAC  address   : 48:45:20:59:a4:0c
                broadcast : ff:ff:ff:ff:ff:ff
    """
    result = ""
    stats = psutil.net_if_stats()
    io_counters = psutil.net_io_counters(pernic=True)
    for nic, addrs in psutil.net_if_addrs().items():
        result = result + "%s:" % (nic) + "\n"
        if nic in stats:
            st = stats[nic]
            result = result + "    stats          : "
            result = result + "speed=%sMB, duplex=%s, mtu=%s, up=%s" % (
                st.speed, duplex_map[st.duplex], st.mtu,
                "yes" if st.isup else "no")
        if nic in io_counters:
            io = io_counters[nic]
            result = result + "\n    incoming       : "
            result = result + "bytes=%s, pkts=%s, errs=%s, drops=%s" % (
                bytes2human(io.bytes_recv), io.packets_recv, io.errin,
                io.dropin)
            result = result + "\n    outgoing       : "
            result = result + "bytes=%s, pkts=%s, errs=%s, drops=%s" % (
                bytes2human(io.bytes_sent), io.packets_sent, io.errout,
                io.dropout)
        for addr in addrs:
            result = result + "\n    %-4s" % af_map.get(addr.family, addr.family)
            result = result + " address   : %s" % addr.address
            if addr.broadcast:
                result = result + "\n         broadcast : %s" % addr.broadcast
            if addr.netmask:
                result = result + "\n         netmask   : %s" % addr.netmask
            if addr.ptp:
                result = result + "\n      p2p       : %s" % addr.ptp
        result = result + "\n"
    return result

#def clean_screen():
    #if psutil.POSIX:
        #os.system('clear')
    #else:
        #os.system('cls')
def cpu_num():
    result = ""
    if not hasattr(psutil, "cpu_count"):
        result = result + "cpu_count on platform not supported"
        return result
    total = psutil.cpu_count()
    result = result + "%s cpu"%total

    #if hasattr(psutil.Process, "cpu_num"):
        #while True:
            ## header
            ##clean_screen()
            #cpus_percent = psutil.cpu_percent(percpu=True)
            #for i in range(total):
                #result = result + "CPU %-6i\n" % i
            #result = result + "\n"
            #for percent in cpus_percent:
                #result = result + "%-10s" % percent
            #result = result + "\n"

            ## processes
            #procs = collections.defaultdict(list)
            #for p in psutil.process_iter(attrs=['name', 'cpu_num']):
                #procs[p.info['cpu_num']].append(p.info['name'][:5])

            #end_marker = [[] for x in range(total)]
            #while True:
                #for num in range(total):
                    #try:
                        #pname = procs[num].pop()
                    #except IndexError:
                        #pname = ""
                    #result = result + "%-10s\n" % pname[:10]
                #result = result + "\n"
                #if procs.values() == end_marker:
                    #break

            #time.sleep(1)
    return result

AD = "-"
AF_INET6 = getattr(socket, 'AF_INET6', object())
proto_map = {
    (AF_INET, SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET, SOCK_DGRAM): 'udp',
    (AF_INET6, SOCK_DGRAM): 'udp6',
}

def netstat():
    """
        A clone of 'netstat -antp' on Linux.

        function netstat
        Proto Local address      Remote address   Status        PID    Program name
        tcp   127.0.0.1:48256    127.0.0.1:45884  ESTABLISHED   13646  chrome
        tcp   127.0.0.1:47073    127.0.0.1:45884  ESTABLISHED   13646  chrome
        tcp   127.0.0.1:47072    127.0.0.1:45884  ESTABLISHED   13646  chrome
        tcp   127.0.0.1:45884    -                LISTEN        13651  GoogleTalkPlugi
        tcp   127.0.0.1:60948    -                LISTEN        13651  GoogleTalkPlugi
        tcp   172.17.42.1:49102  127.0.0.1:19305  CLOSE_WAIT    13651  GoogleTalkPlugi
        tcp   172.17.42.1:55797  127.0.0.1:443    CLOSE_WAIT    13651  GoogleTalkPlugi
    """
    result = ""
    templ = "%-5s %-30s %-30s %-13s %-6s %s\n"
    result = result + templ % (
        "Proto", "Local address", "Remote address", "Status", "PID",
        "Program name")
    proc_names = {}
    for p in psutil.process_iter():
        proc_names[p.pid] = p.name()
    for c in psutil.net_connections(kind='inet'):
        laddr = "%s:%s" % (c.laddr)
        raddr = ""
        if c.raddr:
            raddr = "%s:%s" % (c.raddr)
        result = result + templ % (
            proto_map[(c.family, c.type)],
            laddr,
            raddr or AD,
            c.status,
            c.pid or AD,
            proc_names.get(c.pid, '?')[:15],
        )
    return result

def __dictdata(datatuple):
    result = {}
    # key du tuple
    keyattribut = datatuple.__dict__.keys()
    for keyc in keyattribut:
        #attribut du tuple vers key du dict
        result[keyc]= getattr(datatuple,keyc)
    return result

def cputimes (percpu = False ):
    result = {}
    infocpu =  psutil.cpu_times( percpu = False)
    result['allcpu'] = __dictdata(infocpu)
    if percpu == False:
        #global time (all cpu)
        result['allcpu'] = __dictdata(infocpu)
    elif percpu == True:
        infocpu =  psutil.cpu_times( percpu = percpu)
        nbcpu = len(infocpu)
        result['nbcpu'] = nbcpu
        for cpu_nb in range(0,nbcpu):
            result['cpu%s'% cpu_nb] = __dictdata(infocpu[cpu_nb])
    return result
