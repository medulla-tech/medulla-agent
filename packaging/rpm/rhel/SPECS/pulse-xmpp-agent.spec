%define tarname		pulse-xmpp-agent
%define git                    SHA
%define use_git         1
%define branch integration
%define filetree_version 0.2

Summary:	Pulse XMPP Agent
Name:		pulse-xmpp-agent
Version:	2.1.7
%if ! %use_git
Release:        1%{?dist}
%else
Release:        0.%git.1%{?dist}
%endif

Source0:        %name-%version.tar.gz
License:	MIT

Group:		Development/Python
Url:		http://www.siveo.net

BuildRequires:	python-setuptools
BuildRequires:	python-sphinx
BuildRequires:  git

%description
Pulse XMPP Agent

#--------------------------------------------------------------------

%package -n     pulse-xmpp-agent-relay
Summary:        Pulse 2 common files
Group:          System/Servers
BuildArch:      noarch

Requires(pre):  shadow-utils

Requires:       python-netifaces
Requires:       python-sleekxmpp
Requires:       python-croniter
Requires:       python-requests
Requires:       python2-pysftp
Requires:       python-inotify
Requires:       python-dateutil
Requires:       python2-psutil
Requires:       python-wakeonlan
Requires:       python-crypto
Requires:       python-cherrypy
Requires:       net-tools
Requires:       jq

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
if [ -f "/usr/lib/python2.7/site-packages/pulse_xmpp_agent/BOOL_UPDATE_AGENT" ]; then
    rm -f /usr/lib/python2.7/site-packages/pulse_xmpp_agent/BOOL_UPDATE_AGENT
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

%files -n pulse-xmpp-agent-relay
%_prefix/lib/systemd/system/pulse-xmpp-agent-log.service
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
%_var/log/pulse
%dir %{python2_sitelib}/pulse_xmpp_agent/
%{python2_sitelib}/pulse_xmpp_agent/lib/
%{python2_sitelib}/pulse_xmpp_agent/*.py*
%{python2_sitelib}/pulse_xmpp_agent/script/
%{python2_sitelib}/pulse_xmpp_agent/pluginsrelay/
%{python2_sitelib}/pulse_xmpp_agent/pluginsmachine/
%{python2_sitelib}/pulse_xmpp_agent/agentversion
%{python2_sitelib}/pulse_xmpp_agent/descriptor_scheduler_relay/
%{python2_sitelib}/pulse_xmpp_agent/descriptor_scheduler_machine/

#--------------------------------------------------------------------

%package -n     pulse-xmpp-master-substitute
Summary:        Pulse 2 common files
Group:          System/Servers
Requires:       python-enum34
Requires:       jq
BuildArch:      noarch

%description -n pulse-xmpp-master-substitute
Pulse master agent substitute

%post -n pulse-xmpp-master-substitute
systemctl daemon-reload

%files -n pulse-xmpp-master-substitute
%{python2_sitelib}/pulse_xmpp_master_substitute/
%config(noreplace) %_sysconfdir/pulse-xmpp-agent-substitute/
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-inventory.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-registration.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-assessor.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-subscription.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-logger.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-deployment.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-reconfigurator.service
%_prefix/lib/systemd/system/pulse-xmpp-master-substitute-monitoring.service
%_var/lib/pulse2/script_monitoring/


#--------------------------------------------------------------------

%package -n pulse-agent-installers
Summary:    Files to create pulse windows installer
Group:      System/Servers

Requires:   pulse-xmpp-agent-deps >= 1.8

Requires:   dos2unix
Requires:   unzip
Requires:   zip
Requires:   crudini
Requires:   dpkg-dev

Requires:   nsis-plugins-ZipDLL
Requires:   nsis-plugins-Pwgen
Requires:   nsis-plugins-AccessControl
Requires:   nsis-plugins-Inetc
Requires:   nsis-plugins-TextReplace
Requires(pre): pulse-filetree-generator

%description -n pulse-agent-installers
Files to create pulse windows installer

%pre -n pulse-agent-installers
rm -fv /var/lib/pulse2/imaging/postinst/winutils/Pulse-Agent*latest*

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


%post -n pulse-agent-installers
if [ $1 == 2 ]; then
    if [ -f %_var/lib/pulse2/clients/config/agentconf.ini ]; then
        %_var/lib/pulse2/clients/generate-pulse-agent.sh
        %_var/lib/pulse2/clients/generate-pulse-agent.sh --minimal
        %_var/lib/pulse2/clients/generate-agent-package
    fi
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
%attr(0755,syncthing,syncthing)  %_var/lib/pulse2/xmpp_baseremoteagent/

#--------------------------------------------------------------------

%package -n pulse-xmppmaster-agentplugins
Summary:    Console agent
Group:      System/Servers
Requires:   python-netifaces
Requires:   python-sleekxmpp

%description -n pulse-xmppmaster-agentplugins
plugins for pulse xmppmaster

%files -n pulse-xmppmaster-agentplugins
%_var/lib/pulse2/xmpp_baseplugin
%_var/lib/pulse2/xmpp_basepluginscheduler

#--------------------------------------------------------------------

%package -n pulseagent-plugins-relay
Summary:    Console agent
Group:      System/Servers
Requires:   python-wakeonlan
Requires:   python-netifaces
Requires:   python-sleekxmpp
Requires:   lsof

%description -n pulseagent-plugins-relay
plugins for pulse xmppmaster

%files -n pulseagent-plugins-relay
%python2_sitelib/pulse_xmpp_agent/pluginsrelay
%python2_sitelib/pulse_xmpp_agent/descriptor_scheduler_relay

#--------------------------------------------------------------------

%prep
%setup -q

# Remove bundled egg-info
rm -rf %{tarname}.egg-info

%build
# Nothing to do

%install
mkdir -p %buildroot%{python2_sitelib}/pulse_xmpp_agent
cp -fr pulse_xmpp_agent/* %buildroot%{python2_sitelib}/pulse_xmpp_agent
rm -fr %buildroot%{python2_sitelib}/pulse_xmpp_agent/config
rm -fr %buildroot%{python2_sitelib}/pulse_xmpp_agent/descriptor_scheduler_common
rm -fr %buildroot%{python2_sitelib}/pulse_xmpp_agent/plugins_common
rm -fr %buildroot%{python2_sitelib}/pulse_xmpp_agent/descriptor_scheduler_machine/scheduling_*.py
rm -fr %buildroot%{python2_sitelib}/pulse_xmpp_agent/pluginsmachine/plugin_*.py
cp -fv pulse_xmpp_agent/plugins_common/plugin_* %buildroot%{python2_sitelib}/pulse_xmpp_agent/pluginsrelay
cp -fv pulse_xmpp_agent/descriptor_scheduler_common/scheduling_*.py %buildroot%{python2_sitelib}/pulse_xmpp_agent/descriptor_scheduler_relay/
mkdir -p %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/sessiondeploysubstitute
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/pulse-xmpp-agent-log.py
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/agentxmpp.py
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/package_watching.py
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/launcher.py
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
mkdir -p %buildroot%_sysconfdir/logrotate.d/
cp contrib/scripts/pulse-xmpp-agent-relay.logrotate %buildroot%_sysconfdir/logrotate.d/pulse-xmpp-agent-relay
mkdir -p %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp pulse_xmpp_master_substitute/agentmastersubstitute.py %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp pulse_xmpp_master_substitute/agentversion %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/bin/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/lib/  %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/pluginsmastersubstitute/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/descriptor_scheduler_substitute/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/script/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
mkdir -p %buildroot%_sysconfdir/pulse-xmpp-agent-substitute/
cp pulse_xmpp_master_substitute/config/*.ini %buildroot%_sysconfdir/pulse-xmpp-agent-substitute/
cp -fr pulse_xmpp_master_substitute/config/systemd/* %buildroot%_prefix/lib/systemd/system
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/agentmastersubstitute.py
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
#GIT_SSL_NO_VERIFY=true git clone https://github.com/pulse-project/kiosk-interface.git
#mv kiosk-interface kiosk-interface-${VERSION_KIOSK_INTERFACE}
#tar czvf kiosk-interface-${VERSION_KIOSK_INTERFACE}.tar.gz kiosk-interface-${VERSION_KIOSK_INTERFACE}
#mv kiosk-interface-${VERSION_KIOSK_INTERFACE}.tar.gz var/lib/pulse2/clients
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
cp -fv contrib/monitoring/* %buildroot%_var/lib/pulse2/script_monitoring/
