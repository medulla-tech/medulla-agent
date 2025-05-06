%define __python3 /usr/bin/python3
%define python3_sitelib %(%{__python3} -Ic "from distutils.sysconfig import get_python_lib; print(get_python_lib())")
%define python3_sitearch %(%{__python3} -Ic "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")
%define python3_version %(%{__python3} -Ic "import sys; sys.stdout.write(sys.version[:3])")
%define python3_version_nodots %(%{__python3} -Ic "import sys; sys.stdout.write(sys.version[:3].replace('.',''))")
%define python3_platform %(%{__python3} -Ic "import sysconfig; print(sysconfig.get_platform())")
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

%define tarname		medulla-agent
%define git                    SHA
%define use_git         1
%define branch master
%define filetree_version 0.2
%define kiosk_version 1.0.0

%global __python %{__python3}

Summary:	Pulse XMPP Agent
Name:		medulla-agent
Version:	3.2.1
%if ! %use_git
Release:        1%{?dist}
%else
Release:        0.%git.1%{?dist}
%endif

Source0:        %name-%version.tar.bz2
License:	MIT

Group:		Development/Python
Url:		http://www.siveo.net

BuildArch:	noarch

BuildRequires:	python3.11-setuptools
BuildRequires:  git

%description
Pulse XMPP Agent

#--------------------------------------------------------------------

%package -n     pulse-xmpp-agent-relay
Summary:        Pulse 2 common files
Group:          System/Servers
BuildArch:      noarch

Requires(pre):  shadow-utils

Requires:       python3.11-netifaces
Requires:       python3.11-slixmpp
Requires:       python3.11-croniter
Requires:       python3.11-requests
Requires:       python3.11-inotify
Requires:       python3.11-dateutil
Requires:       python3.11-psutil
Requires:       python3.11-wakeonlan
Requires:       python3.11-cryptodome
Requires:       python3.11-cherrypy
Requires:       python3.11-pycurl
Requires:       net-tools
Requires:       jq
Requires:       python3.11-distro
Requires:       python3.11-lmdb
Requires:       python3.11-xmltodict
Requires:       python3.11-netaddr
Requires:       python3.11-more-itertools
Requires:       python3.11-jaraco-collections
Requires:       python3.11-jaraco-classes
Requires:       python3.11-jaraco-text
Requires:       python3.11-jaraco-context
Requires:       python3.11-jaraco-functools
Requires:       python3.11-backports-tarfile
Requires:       python3.11-zc-lockfile
Requires:       python3.11-cheroot
Requires:       python3.11-portend
Requires:       python3.11-tempora
Requires:       python3.11-posix-ipc
Obsoletes:     pulse-xmpp-agent < 2.0.7
Provides:      pulse-xmpp-agent = %version

Obsoletes:     pulseagent-plugins-relay < 2.0.7
Provides:      pulseagent-plugins-relay = %version

%description -n pulse-xmpp-agent-relay
Pulse master agent substitute

%pre -n     pulse-xmpp-agent-relay
if ! getent passwd | grep -q "^reversessh:"; then
    echo -n "Adding user reversessh..."
    adduser --system \
        -d /var/lib/pulse2/clients/reversessh \
        -s /bin/rbash \
        reversessh
    echo "..done"
fi

if [ ! -f "/var/lib/pulse2/clients/reversessh/.ssh/id_rsa" ]; then
    echo -n "Generating ssh key..."
    mkdir -p /var/lib/pulse2/clients/reversessh/.ssh
    ssh-keygen -q -N "" -b 2048 -t rsa -f /var/lib/pulse2/clients/reversessh/.ssh/id_rsa
    cp -a /var/lib/pulse2/clients/reversessh/.ssh/id_rsa.pub /var/lib/pulse2/clients/reversessh/.ssh/authorized_keys
    chown -R reversessh: /var/lib/pulse2/clients/reversessh/.ssh
    chmod 700 /var/lib/pulse2/clients/reversessh/.ssh
    chmod 600 /var/lib/pulse2/clients/reversessh/.ssh/authorized_keys
    echo "..done"
fi

%post -n pulse-xmpp-agent-relay
if [ -f "/usr/lib/python3.5/site-packages/pulse_xmpp_agent/BOOL_UPDATE_AGENT" ]; then
    rm -f /usr/lib/python3.5/site-packages/pulse_xmpp_agent/BOOL_UPDATE_AGENT
fi

if systemctl -q is-enabled pulse-xmpp-master-substitute-inventory ; then
    echo -n "Restarting pulse-xmpp-master-substitute-inventory service..."
    systemctl restart pulse-xmpp-master-substitute-inventory
    echo "..done"
fi

if systemctl -q is-enabled pulse-xmpp-master-substitute-registration ; then
    echo -n "Restarting pulse-xmpp-master-substitute-registration service..."
    systemctl restart pulse-xmpp-master-substitute-registration
    echo "..done"
fi

if systemctl -q is-enabled pulse-xmpp-master-substitute-assessor ; then
    echo -n "Restarting pulse-xmpp-master-substitute-assessor service..."
    systemctl restart pulse-xmpp-master-substitute-assessor
    echo "..done"
fi

if systemctl -q is-enabled pulse-xmpp-master-substitute-deployment ; then
    echo -n "Restarting pulse-xmpp-master-substitute-deployment service..."
    systemctl restart pulse-xmpp-master-substitute-deployment
    echo "..done"
fi

if systemctl -q is-enabled pulse-xmpp-master-substitute-subscription ; then
    echo -n "Restarting pulse-xmpp-master-substitute-subscription service..."
    systemctl restart pulse-xmpp-master-substitute-subscription
    echo "..done"
fi

if systemctl -q is-enabled pulse-xmpp-master-substitute-logger ; then
    echo -n "Restarting pulse-xmpp-master-substitute-logger service..."
    systemctl restart pulse-xmpp-master-substitute-logger
    echo "..done"
fi

if systemctl -q is-enabled pulse-xmpp-master-substitute-reconfigurator ; then
    echo -n "Restarting pulse-xmpp-master-substitute-reconfigurator service..."
    systemctl restart pulse-xmpp-master-substitute-reconfigurator
    echo "..done"
fi

if systemctl -q is-enabled pulse-xmpp-master-substitute-monitoring ; then
    echo -n "Restarting pulse-xmpp-master-substitute-monitoring service..."
    systemctl restart pulse-xmpp-master-substitute-monitoring
    echo "..done"
fi

if systemctl -q is-enabled pulse-xmpp-master-substitute-updates ; then
    echo -n "Restarting pulse-xmpp-master-substitute-updates service..."
    systemctl restart pulse-xmpp-master-substitute-updates
    echo "..done"
fi

%files -n pulse-xmpp-agent-relay
%_prefix/lib/systemd/system/pulse-xmpp-agent-relay.service
%_prefix/lib/systemd/system/pulse-package-watching.service
%dir %_sysconfdir/pulse-xmpp-agent/
%_sysconfdir/logrotate.d/pulse-xmpp-agent-relay
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/guacamoleconf.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/downloadfile.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/downloadfileexpert.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/applicationdeploymentjson.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/guacamole.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/reverse_ssh_on.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/wakeonlan.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/relayconf.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/package_watching.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/manage_scheduler_relay.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/start_relay.ini
%config(noreplace) %_sysconfdir/pulse-xmpp-agent/ars___server_tcpip.ini
%_var/log/pulse
%dir %{python3_sitelib}/pulse_xmpp_agent/
%{python3_sitelib}/pulse_xmpp_agent/lib/
%{python3_sitelib}/pulse_xmpp_agent/*.py*
%{python3_sitelib}/pulse_xmpp_agent/script/
%{python3_sitelib}/pulse_xmpp_agent/pluginsrelay/
%{python3_sitelib}/pulse_xmpp_agent/pluginsmachine/
%{python3_sitelib}/pulse_xmpp_agent/agentversion
%{python3_sitelib}/pulse_xmpp_agent/descriptor_scheduler_relay/
%{python3_sitelib}/pulse_xmpp_agent/descriptor_scheduler_machine/
%_sbindir/medulla_info_update.py

#--------------------------------------------------------------------

%package -n     pulse-xmpp-master-substitute
Summary:        Pulse 2 common files
Group:          System/Servers
Requires:       python3.11-xmltodict
Requires:       python3.11-croniter
Requires:       jq
BuildArch:      noarch

%description -n pulse-xmpp-master-substitute
Pulse master agent substitute

%post -n pulse-xmpp-master-substitute
systemctl daemon-reload

%files -n pulse-xmpp-master-substitute
%{python3_sitelib}/pulse_xmpp_master_substitute/
%config(noreplace) %_sysconfdir/pulse-xmpp-agent-substitute/
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-inventory.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-registration.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-assessor.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-subscription.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-logger.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-deployment.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-reconfigurator.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-monitoring.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-master.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-updates.service
%_var/lib/pulse2/script_monitoring/
%_var/lib/pulse2/xml_fix

#--------------------------------------------------------------------

%package -n pulse-agent-installers
Summary:    Files to create pulse windows installer
Group:      System/Servers

Requires:   medulla-agent-deps >= 1.8

Requires:   dos2unix
Requires:   unzip
Requires:   zip
Requires:   crudini
#Requires:  dpkg-dev

#Requires:   nsis-plugins-ZipDLL
#Requires:   nsis-plugins-Pwgen
#Requires:   nsis-plugins-AccessControl
#Requires:   nsis-plugins-Inetc
#Requires:   nsis-plugins-TextReplace
Requires(pre): pulse-filetree-generator

%description -n pulse-agent-installers
Files to create pulse windows installer

%pre -n pulse-agent-installers
rm -fv /var/lib/pulse2/imaging/postinst/winutils/Medulla-Agent*latest*

if [ ! -d "/var/lib/pulse2/clients/win" ]; then
    mkdir /var/lib/pulse2/clients/win
fi

if [ -d "/var/lib/pulse2/clients/win32" ]; then
    mv /var/lib/pulse2/clients/win32/*.exe /var/lib/pulse2/clients/win/
    rm -fr /var/lib/pulse2/clients/win32/
fi

if [ -d "/var/lib/pulse2/clients/linux" ]; then
    rm -fr /var/lib/pulse2/clients/linux/
fi


%files -n pulse-agent-installers
%_var/lib/pulse2/clients
%config(noreplace) %_var/lib/pulse2/clients/config/agentconf.ini
%config(noreplace) %_var/lib/pulse2/clients/config/manage_scheduler_machine.ini
%config(noreplace) %_var/lib/pulse2/clients/config/inventory.ini
%config(noreplace) %_var/lib/pulse2/clients/config/start_machine.ini
%config(noreplace) %_var/lib/pulse2/clients/config/startupdate.ini
%config(noreplace) %_var/lib/pulse2/clients/config/updateopenssh.ini
%config(noreplace) %_var/lib/pulse2/clients/config/updatetightvnc.ini
%config(noreplace) %_var/lib/pulse2/clients/config/updatebackupclient.ini
%config(noreplace) %_var/lib/pulse2/clients/config/am___server_tcpip.ini
%attr(0755,syncthing,syncthing)  %_var/lib/pulse2/xmpp_baseremoteagent/
%attr(0755,syncthing,syncthing)  %_var/lib/pulse2/clients/

#--------------------------------------------------------------------

%package -n pulse-xmppmaster-agentplugins
Summary:    Console agent
Group:      System/Servers
Requires:   python3.11-netifaces
Requires:   python3.11-slixmpp

%description -n pulse-xmppmaster-agentplugins
plugins for pulse xmppmaster

%files -n pulse-xmppmaster-agentplugins
%_var/lib/pulse2/xmpp_baseplugin
%_var/lib/pulse2/xmpp_basepluginscheduler

#--------------------------------------------------------------------

%package -n pulseagent-plugins-relay
Summary:    Console agent
Group:      System/Servers
Requires:   python3.11-wakeonlan
Requires:   python3.11-netifaces
Requires:   python3.11-slixmpp
Requires:   lsof

%description -n pulseagent-plugins-relay
plugins for pulse xmppmaster

%files -n pulseagent-plugins-relay
%python3_sitelib/pulse_xmpp_agent/pluginsrelay
%python3_sitelib/pulse_xmpp_agent/descriptor_scheduler_relay

#--------------------------------------------------------------------

%prep
%setup -q -n %name

# Remove bundled egg-info
rm -rf %{tarname}.egg-info

%build
# Nothing to do

%install
mkdir -p %buildroot%{python3_sitelib}/pulse_xmpp_agent
cp -fr pulse_xmpp_agent/* %buildroot%{python3_sitelib}/pulse_xmpp_agent
rm -fr %buildroot%{python3_sitelib}/pulse_xmpp_agent/config
rm -fr %buildroot%{python3_sitelib}/pulse_xmpp_agent/descriptor_scheduler_common
rm -fr %buildroot%{python3_sitelib}/pulse_xmpp_agent/plugins_common
rm -fr %buildroot%{python3_sitelib}/pulse_xmpp_agent/descriptor_scheduler_machine/scheduling_*.py
rm -fr %buildroot%{python3_sitelib}/pulse_xmpp_agent/pluginsmachine/plugin_*.py
cp -fv pulse_xmpp_agent/plugins_common/plugin_* %buildroot%{python3_sitelib}/pulse_xmpp_agent/pluginsrelay
cp -fv pulse_xmpp_agent/descriptor_scheduler_common/scheduling_*.py %buildroot%{python3_sitelib}/pulse_xmpp_agent/descriptor_scheduler_relay/
chmod +x %buildroot%{python3_sitelib}/pulse_xmpp_agent/agentxmpp.py
chmod +x %buildroot%{python3_sitelib}/pulse_xmpp_agent/package_watching.py
chmod +x %buildroot%{python3_sitelib}/pulse_xmpp_agent/launcher.py
mkdir -p %buildroot%_var/log/pulse/
mkdir -p %buildroot%_prefix/lib/systemd/system
mkdir -p %buildroot%_var/lib/pulse2/clients/config/
cp -fr pulse_xmpp_agent/config/systemd/* %buildroot%_prefix/lib/systemd/system
cp -fv ./scripts_installer/lin/*.service %buildroot%_prefix/lib/systemd/system
rm -fv %buildroot%_prefix/lib/systemd/system/pulse-xmpp-agent-machine.service
mkdir -p %buildroot%_var/lib/pulse2/xmpp_baseplugin
mkdir -p %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
cp -frv pulse_xmpp_agent/plugins_common/plugin_* %buildroot%_var/lib/pulse2/xmpp_baseplugin
cp -frv pulse_xmpp_agent/pluginsmachine/plugin_* %buildroot%_var/lib/pulse2/xmpp_baseplugin
cp -frv pulse_xmpp_agent/pluginsrelay/plugin_* %buildroot%_var/lib/pulse2/xmpp_baseplugin
cp -fv  pulse_xmpp_agent/descriptor_scheduler_common/scheduling_* %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler	
cp -fv  pulse_xmpp_agent/descriptor_scheduler_machine/scheduling_* %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
cp -fv  pulse_xmpp_agent/descriptor_scheduler_relay/scheduling_* %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
mkdir -p %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/guacamoleconf.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/downloadfile.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/downloadfileexpert.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/applicationdeploymentjson.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/guacamole.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/reverse_ssh_on.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/wakeonlan.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/relayconf.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/package_watching.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/manage_scheduler_relay.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/start_relay.ini %buildroot%_sysconfdir/pulse-xmpp-agent
cp pulse_xmpp_agent/config/ars___server_tcpip.ini %buildroot%_sysconfdir/pulse-xmpp-agent
mkdir -p %buildroot%_sysconfdir/logrotate.d/
cp contrib/scripts/pulse-xmpp-agent-relay.logrotate %buildroot%_sysconfdir/logrotate.d/pulse-xmpp-agent-relay
mkdir -p %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/
cp pulse_xmpp_master_substitute/agentmastersubstitute.py %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/
cp pulse_xmpp_master_substitute/agentversion %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/bin/ %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/lib/  %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/pluginsmastersubstitute/ %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/script/ %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/
mkdir -p %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/sessiondeploysubstitute/
touch %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/sessiondeploysubstitute/EMPTY
mkdir -p %buildroot%_sysconfdir/pulse-xmpp-agent-substitute/
cp pulse_xmpp_master_substitute/config/*.ini %buildroot%_sysconfdir/pulse-xmpp-agent-substitute/
cp -fr pulse_xmpp_master_substitute/config/systemd/* %buildroot%_prefix/lib/systemd/system
chmod +x %buildroot%{python3_sitelib}/pulse_xmpp_master_substitute/agentmastersubstitute.py
# We create the installer part now
mkdir pulse-xmpp-agent-%{version}
mkdir -p pulse-machine-plugins-%{version}/pulse_xmpp_agent/pluginsmachine
mkdir -p pulse-machine-plugins-%{version}/pulse_xmpp_agent/descriptor_scheduler_machine
cp -frv pulse_xmpp_agent pulse-xmpp-agent-%{version}/
cp -fv packaging/python/agent_setup.py pulse-xmpp-agent-%{version}/setup.py
cp -fv packaging/python/machineplugins_setup.py pulse-machine-plugins-%{version}/setup.py
cp -fv packaging/python/LICENSE pulse-xmpp-agent-%{version}
cp -fv packaging/python/README.md pulse-xmpp-agent-%{version}
cp -fv packaging/python/MANIFEST.in pulse-xmpp-agent-%{version}
cp -fv packaging/python/LICENSE pulse-machine-plugins-%{version}
cp -fv packaging/python/README.md pulse-machine-plugins-%{version}	
rm -fr pulse-xmpp-agent-%{version}/pulse_xmpp_agent/config
mv pulse-xmpp-agent-%{version}/pulse_xmpp_agent/plugins_common/plugin_*.py pulse-machine-plugins-%{version}/pulse_xmpp_agent/pluginsmachine
mv pulse-xmpp-agent-%{version}/pulse_xmpp_agent/descriptor_scheduler_common/scheduling_*.py pulse-machine-plugins-%{version}/pulse_xmpp_agent/descriptor_scheduler_machine
mv pulse-xmpp-agent-%{version}/pulse_xmpp_agent/pluginsmachine/plugin_*.py pulse-machine-plugins-%{version}/pulse_xmpp_agent/pluginsmachine
mv pulse-xmpp-agent-%{version}/pulse_xmpp_agent/descriptor_scheduler_machine/scheduling_*.py pulse-machine-plugins-%{version}/pulse_xmpp_agent/descriptor_scheduler_machine
rm -fr pulse-xmpp-agent-%{version}/pulse_xmpp_agent/descriptor_scheduler_common/
rm -fr pulse-xmpp-agent-%{version}/pulse_xmpp_agent/descriptor_scheduler_relay/scheduling_*.py
rm -fr pulse-xmpp-agent-%{version}/pulse_xmpp_agent/plugins_common/
rm -fr pulse-xmpp-agent-%{version}/pulse_xmpp_agent/pluginsrelay/plugin_*.py
tar czvf pulse-xmpp-agent-%{version}.tar.gz pulse-xmpp-agent-%{version}
rm -fr pulse-xmpp-agent-%{version}
tar czvf pulse-machine-plugins-%{version}.tar.gz pulse-machine-plugins-%{version}
rm -fr pulse-machine-plugins-%{version}
mkdir -p %buildroot%_var/lib/pulse2/clients
mv  pulse-xmpp-agent-%{version}.tar.gz %buildroot%_var/lib/pulse2/clients
mv  pulse-machine-plugins-%{version}.tar.gz %buildroot%_var/lib/pulse2/clients
GIT_SSL_NO_VERIFY=true git clone --branch %branch https://github.com/pulse-project/kiosk-interface.git
mv kiosk-interface kiosk-interface-%{kiosk_version}
tar czvf kiosk-interface-%{kiosk_version}.tar.gz kiosk-interface-%{kiosk_version}
rm -fr kiosk-interface-%{kiosk_version}
mv kiosk-interface-%{kiosk_version}.tar.gz %buildroot%_var/lib/pulse2/clients
mkdir -p %buildroot%_var/lib/pulse2/xmpp_baseremoteagent
cp -frv pulse_xmpp_agent/* %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/
rm -frv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/config
rm -frv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/descriptor_scheduler_common
rm -frv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/plugins_common
rm -fv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/descriptor_scheduler_machine/scheduling_*.py
rm -fv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/pluginsmachine/plugin_*.py
rm -fv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/descriptor_scheduler_relay/scheduling_*.py
rm -fv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/pluginsrelay/plugin_*.py
mkdir -p %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/agentconf.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/manage_scheduler_machine.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/inventory.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/start_machine.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/startupdate.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/updateopenssh.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/updatetightvnc.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/updatebackupclient.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/am___server_tcpip.ini %buildroot%_var/lib/pulse2/clients/config/
cp scripts_installer/generate-pulse-agent.sh %buildroot%_var/lib/pulse2/clients
cp scripts_installer/generate-agent-package %buildroot%_var/lib/pulse2/clients
cp scripts_installer/HEADER.html %buildroot%_var/lib/pulse2/clients
cp scripts_installer/style.css %buildroot%_var/lib/pulse2/clients
mkdir -p %buildroot%_var/lib/pulse2/clients/win
cp scripts_installer/win/generate-pulse-agent-win.sh %buildroot%_var/lib/pulse2/clients/win
cp scripts_installer/win/agent-installer.nsi.in %buildroot%_var/lib/pulse2/clients/win
cp scripts_installer/win/pulse-agent-task.xml %buildroot%_var/lib/pulse2/clients/win
chmod +x %buildroot%_var/lib/pulse2/clients/win/generate-pulse-agent-win.sh
mkdir -p %buildroot%_var/lib/pulse2/clients/lin
cp scripts_installer/lin/generate-pulse-agent-linux.sh %buildroot%_var/lib/pulse2/clients/lin
chmod +x %buildroot%_var/lib/pulse2/clients/lin/generate-pulse-agent-linux.sh
mkdir -p %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/generate-pulse-agent-mac.sh %buildroot%_var/lib/pulse2/clients/mac
chmod +x %buildroot%_var/lib/pulse2/clients/mac/generate-pulse-agent-mac.sh
mkdir -p %buildroot%_var/lib/pulse2/clients/lin
cp -r scripts_installer/lin/* %buildroot%_var/lib/pulse2/clients/lin
mkdir -p %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/generate-pulse-agent-mac.sh %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/Info.plist.in %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/postflight.in %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/net.siveo.pulse_xmpp_agent.plist %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/rbash %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/runpulseagent %buildroot%_var/lib/pulse2/clients/mac
mkdir -p %buildroot%_var/lib/pulse2/clients/win/libs
cp -fr scripts_installer/win/nsis_libs/* %buildroot%_var/lib/pulse2/clients/win/libs
mkdir -p %buildroot%_var/lib/pulse2/clients/win/artwork
cp -fr scripts_installer/win/artwork/* %buildroot%_var/lib/pulse2/clients/win/artwork
chmod +x %buildroot%_var/lib/pulse2/clients/*.sh
chmod +x %buildroot%_var/lib/pulse2/clients/generate-agent-package
cp pulse_xmpp_agent/script/create-profile.ps1 %buildroot%_var/lib/pulse2/clients/win/
cp pulse_xmpp_agent/script/remove-profile.ps1 %buildroot%_var/lib/pulse2/clients/win/
cp scripts_installer/win/pulse-service.py %buildroot%_var/lib/pulse2/clients/win/
cp scripts_installer/win/netcheck-service.py %buildroot%_var/lib/pulse2/clients/win/
cp scripts_installer/win/networkevents.py %buildroot%_var/lib/pulse2/clients/win/
cp scripts_installer/win/powershell-policy-remotesigned.pol %buildroot%_var/lib/pulse2/clients/win/
mkdir -p %buildroot%_var/lib/pulse2/script_monitoring
cp -fv contrib/monitoring/readme %buildroot%_var/lib/pulse2/script_monitoring/
cp -fv contrib/monitoring/schema_mon_pulsesystem.sql %buildroot%_var/lib/pulse2/script_monitoring/
cp -fv contrib/monitoring/template_alert_email_html_test.py %buildroot%_var/lib/pulse2/script_monitoring/
cp -fv contrib/monitoring/template_consolidate_online_machines_count.py %buildroot%_var/lib/pulse2/script_monitoring/
cp -fv contrib/monitoring/template_script_bash_test.sh %buildroot%_var/lib/pulse2/script_monitoring/
cp -fv contrib/monitoring/template_script_python_test.py %buildroot%_var/lib/pulse2/script_monitoring/
cp -fv contrib/monitoring/template_script_remote_bash_test.sh %buildroot%_var/lib/pulse2/script_monitoring/
cp -fv contrib/monitoring/template_script_remote_python_test.py %buildroot%_var/lib/pulse2/script_monitoring/
cp pulse_xmpp_agent/bin/pulse2_update_notification.py %buildroot%_var/lib/pulse2/clients/win/
cp pulse_xmpp_agent/bin/pulse2_update_notification.py %buildroot%_var/lib/pulse2/clients/lin/
cp pulse_xmpp_agent/bin/pulse2_update_notification.py %buildroot%_var/lib/pulse2/clients/mac/
cp pulse_xmpp_agent/bin/medulla_info_update.py %buildroot%_sbindir/
cp contrib/images/* %buildroot%_var/lib/pulse2/clients/win/
cp pulse_xmpp_agent/bin/medulla_info_update.py %buildroot%_var/lib/pulse2/clients/win
cp pulse_xmpp_agent/bin/uninstall_medulla_info_update_notification.py %buildroot%_var/lib/pulse2/clients/win

sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-agent-relay.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-package-watching.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-assessor.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-deployment.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-inventory.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-logger.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-master.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-monitoring.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-reconfigurator.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-registration.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-subscription.service
sed -i 's,PATH,%python3_sitelib,g' -i %buildroot%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-updates.service

mkdir -p %buildroot%_var/lib/pulse2/xml_fix
cp -frv contrib/inventory/xml-fix/* %buildroot%_var/lib/pulse2/xml_fix

# Not needed in the server
rm -fv %buildroot%{python3_sitelib}/pulse_xmpp_agent/bin/pulse2_update_notification.py
