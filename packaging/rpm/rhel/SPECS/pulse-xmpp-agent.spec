%define tarname		pulse-xmpp-agent
%define git                    SHA
%define use_git         1
%define branch integration
%define filetree_version 0.2

Summary:	Pulse XMPP Agent
Name:		pulse-xmpp-agent
Version:	2.0.6
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

Requires:       python-netifaces
Requires:       python-sleekxmpp
Requires:       python-croniter
Requires:       python-requests
Requires:       python2-pysftp
Requires:       python-inotify
Requires:       python-dateutil
Requires:       python2-psutil

%description
Pulse XMPP Agent

#--------------------------------------------------------------------

%package -n     pulse-xmpp-agent-relay
Summary:        Pulse 2 common files
Group:          System/Servers
BuildArch:      noarch

Obsoletes:     pulse-xmpp-agent < 2.0.6
Provides:      pulse-xmpp-agent = %version

Obsoletes:     pulseagent-plugins-relay < 2.0.6
Provides:      pulseagent-plugins-relay = %version

%description -n pulse-xmpp-agent-relay
Pulse master agent substitute

%files -n pulse-xmpp-agent-relay
%_prefix/lib/systemd/system/pulse-xmpp-agent-log.service
%_prefix/lib/systemd/system/pulse-xmpp-agent-relay.service
%_prefix/lib/systemd/system/pulse-package-watching.service
%_sysconfdir/pulse-xmpp-agent
%_var/lib/pulse2/clients/config/*
%_var/log/pulse
#%{python2_sitelib}/pulse_xmpp_agent

#--------------------------------------------------------------------

%package -n     pulse-xmpp-master-substitute
Summary:        Pulse 2 common files
Group:          System/Servers
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


#--------------------------------------------------------------------

%package -n pulse-agent-installers
Summary:    Files to create pulse windows installer
Group:      System/Servers

Requires:   pulse-xmpp-agent-deps

Requires:   dos2unix
Requires:   unzip
Requires:   zip
Requires:   crudini

Requires:   nsis-plugins-ZipDLL
Requires:   nsis-plugins-Pwgen
Requires:   nsis-plugins-AccessControl
Requires:   nsis-plugins-Inetc
Requires:   nsis-plugins-TextReplace


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
%_var/lib/pulse2/xmpp_baseremoteagent/

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
%_var/lib/pulse2/clients/config/
%_var/lib/pulse2/clients/config/inventory.ini

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
%_var/lib/pulse2/clients/config/
%_var/lib/pulse2/clients/config/guacamoleconf.ini
%_var/lib/pulse2/clients/config/downloadfile.ini
%_var/lib/pulse2/clients/config/downloadfileexpert.ini

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
mkdir -p %buildroot%_var/log/pulse/
mkdir -p %buildroot%_prefix/lib/systemd/system
mkdir -p %buildroot%_var/lib/pulse2/clients/config/
cp -fr pulse_xmpp_agent/config/systemd/* %buildroot%_prefix/lib/systemd/system
cp -fv ./scripts_installer/lin/*.service %buildroot%_prefix/lib/systemd/system
mkdir -p %buildroot%_var/lib/pulse2/xmpp_baseplugin
mkdir -p %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
cp -frv pulse_xmpp_agent/plugins_common/plugin_* %buildroot%_var/lib/pulse2/xmpp_baseplugin
cp -frv pulse_xmpp_agent/pluginsmachine/plugin_* %buildroot%_var/lib/pulse2/xmpp_baseplugin
cp -frv pulse_xmpp_agent/pluginsrelay/plugin_* %buildroot%_var/lib/pulse2/xmpp_baseplugin
cp -fv  pulse_xmpp_agent/descriptor_scheduler_common/scheduling_* %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
cp -fv  pulse_xmpp_agent/descriptor_scheduler_machine/scheduling_* %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
cp -fv  pulse_xmpp_agent/descriptor_scheduler_relay/scheduling_* %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
mkdir -p %buildroot%{python2_sitelib}/pulse_xmpp_agent/pluginsrelay
cp -fv pulse_xmpp_agent/plugins_common/plugin_* %buildroot%{python2_sitelib}/pulse_xmpp_agent/pluginsrelay
cp -fr pulse_xmpp_agent/pluginsrelay/plugin_* %buildroot%{python2_sitelib}/pulse_xmpp_agent/pluginsrelay
mkdir -p %buildroot%{python2_sitelib}/pulse_xmpp_agent/descriptor_scheduler_relay/
cp -fv pulse_xmpp_agent/descriptor_scheduler_relay/scheduling_*.py %buildroot%{python2_sitelib}/pulse_xmpp_agent/descriptor_scheduler_relay/
cp -fv pulse_xmpp_agent/descriptor_scheduler_common/scheduling_*.py %buildroot%{python2_sitelib}/pulse_xmpp_agent/descriptor_scheduler_relay/
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
mkdir -p %buildroot%_sysconfdir/logrotate.d/
cp contrib/scripts/pulse-xmpp-agent-relay.logrotate %buildroot%_sysconfdir/logrotate.d/pulse-xmpp-agent-relay
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/pulse-xmpp-agent-log.py
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/agentxmpp.py
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/package_watching.py
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/launcher.py
mkdir -p %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp pulse_xmpp_master_substitute/agentmastersubstitute.py %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp pulse_xmpp_master_substitute/agentversion %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/bin/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/lib/  %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/pluginsmastersubstitute/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/script/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
mkdir -p %buildroot%_sysconfdir/pulse-xmpp-agent-substitute/
cp pulse_xmpp_master_substitute/config/*.ini %buildroot%_sysconfdir/pulse-xmpp-agent-substitute/
cp -fr pulse_xmpp_master_substitute/config/systemd/* %buildroot%_prefix/lib/systemd/system
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/agentmastersubstitute.py
# We create the installer part now
mkdir -p tmp
GIT_SSL_NO_VERIFY=true git clone https://github.com/pulse-project/pulse-xmpp-agent.git -b %{branch}
mv pulse-xmpp-agent pulse-xmpp-agent-%{version}
tar czvf pulse-xmpp-agent-%{version}.tar.gz pulse-xmpp-agent-%{version}
rm -fr pulse-xmpp-agent/
mkdir -p %buildroot%_var/lib/pulse2/clients
mv  pulse-xmpp-agent-%{version}.tar.gz %buildroot%_var/lib/pulse2/clients
#GIT_SSL_NO_VERIFY=true git clone https://github.com/pulse-project/kiosk-interface.git
#mv kiosk-interface kiosk-interface-${VERSION_KIOSK_INTERFACE}
#tar czvf kiosk-interface-${VERSION_KIOSK_INTERFACE}.tar.gz kiosk-interface-${VERSION_KIOSK_INTERFACE}
#mv kiosk-interface-${VERSION_KIOSK_INTERFACE}.tar.gz var/lib/pulse2/clients
tar xzf %buildroot%_var/lib/pulse2/clients/pulse-xmpp-agent-%{version}.tar.gz -C tmp
mkdir -p %buildroot%_var/lib/pulse2/xmpp_baseremoteagent
cp -frv pulse_xmpp_agent/* %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/
rm -fv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/managedbkiosk.py
mkdir -p %buildroot%_sysconfdir/mmc/plugins/
mkdir -p %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/agentconf.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/manage_scheduler.ini %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/inventory.ini var/lib/pulse2/clients/config/
cp scripts_installer/generate-pulse-agent.sh %buildroot%_var/lib/pulse2/clients
cp scripts_installer/generate-agent-package %buildroot%_var/lib/pulse2/clients
cp scripts_installer/generate-agent-deps-package %buildroot%_var/lib/pulse2/clients
cp scripts_installer/generate-netcheck-package %buildroot%_var/lib/pulse2/clients
cp scripts_installer/generate-service-package %buildroot%_var/lib/pulse2/clients
cp scripts_installer/HEADER.html %buildroot%_var/lib/pulse2/clients
cp scripts_installer/style.css %buildroot%_var/lib/pulse2/clients
mkdir -p %buildroot%_var/lib/pulse2/clients/win
cp scripts_installer/win/generate-pulse-agent-win.sh %buildroot%_var/lib/pulse2/clients/win
cp scripts_installer/win/agent-installer.nsi.in %buildroot%_var/lib/pulse2/clients/win
cp scripts_installer/win/pulse-agent-task.xml %buildroot%_var/lib/pulse2/clients/win
cp scripts_installer/win/pulse-filetree-generator.exe %buildroot%_var/lib/pulse2/clients/win
chmod +x %buildroot%_var/lib/pulse2/clients/win/generate-pulse-agent-win.sh
mkdir -p %buildroot%_var/lib/pulse2/clients/lin
cp scripts_installer/lin/generate-pulse-agent-linux.sh %buildroot%_var/lib/pulse2/clients/lin
chmod +x %buildroot%_var/lib/pulse2/clients/lin/generate-pulse-agent-linux.sh
mkdir -p %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/generate-pulse-agent-mac.sh %buildroot%_var/lib/pulse2/clients/mac
chmod +x %buildroot%_var/lib/pulse2/clients/mac/generate-pulse-agent-mac.sh
#cp scripts_installer/generate-kiosk-package var/lib/pulse2/clients/win
#chmod +x %buildroot%_var/lib/pulse2/clients/mac/generate-kiosk-package
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
chmod +x %buildroot%_var/lib/pulse2/clients/generate-agent-deps-package
chmod +x %buildroot%_var/lib/pulse2/clients/generate-netcheck-package
chmod +x %buildroot%_var/lib/pulse2/clients/generate-service-package
#chmod +x %buildroot%_var/lib/pulse2/clients/win/generate-kiosk-package
GIT_SSL_NO_VERIFY=true git clone https://github.com/pulse-project/pulse-filetree-generator.git
mv pulse-filetree-generator pulse-filetree-generator-%{filetree_version}
g++ -O3 -std=c++11 pulse-filetree-generator-%{filetree_version}/linux_macos/pulse-filetree-generator.cpp -o pulse-filetree-generator
mkdir -p %buildroot%_var/lib/pulse2/clients/lin/deb/pulse-agent-linux/usr/sbin
cp pulse-filetree-generator %buildroot%_var/lib/pulse2/clients/lin/deb/pulse-agent-linux/usr/sbin
chmod +x %buildroot%_var/lib/pulse2/clients/lin/deb/pulse-agent-linux/usr/sbin/pulse-filetree-generator
mkdir -p %buildroot%_var/lib/pulse2/clients/lin/rpm/package/SOURCES
cp pulse-filetree-generator %buildroot%_var/lib/pulse2/clients/lin/rpm/package/SOURCES
chmod +x %buildroot%_var/lib/pulse2/clients/lin/rpm/package/SOURCES/pulse-filetree-generator
mv pulse-filetree-generator %buildroot%_var/lib/pulse2/clients/mac
chmod +x %buildroot%_var/lib/pulse2/clients/mac/pulse-filetree-generator
cp scripts_installer/win/create-profile.ps1 %buildroot%_var/lib/pulse2/clients/win/
cp scripts_installer/win/pulse-service.py %buildroot%_var/lib/pulse2/clients/win/
cp scripts_installer/win/netcheck-service.py %buildroot%_var/lib/pulse2/clients/win/
cp scripts_installer/win/networkevents.py %buildroot%_var/lib/pulse2/clients/win/
