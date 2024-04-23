%define __python3 /usr/bin/python3
%define python3_sitelib %(%{__python3} -Ic "from distutils.sysconfig import get_python_lib; print(get_python_lib())")
%define python3_sitearch %(%{__python3} -Ic "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")
%define python3_version %(%{__python3} -Ic "import sys; sys.stdout.write(sys.version[:3])")
%define python3_version_nodots %(%{__python3} -Ic "import sys; sys.stdout.write(sys.version[:3].replace('.',''))")
%define python3_platform %(%{__python3} -Ic "import sysconfig; print(sysconfig.get_platform())")


%define tarname		medulla-agent
%define git                    SHA
%define use_git         1
%define branch integration
%define filetree_version 0.2
%define kiosk_version 1.0.0

%global __python %{__python3}

Summary:	Medulla XMPP Agent
Name:		medulla-agent
Version:	3.1.0
%if ! %use_git
Release:        1%{?dist}
%else
Release:        0.%git.1%{?dist}
%endif

Source0:        %name-%version.tar.gz
License:	MIT

Group:		Development/Python
Url:		http://www.siveo.net

BuildRequires:	python3-setuptools
BuildRequires:  git

%description
Medulla XMPP Agent

#--------------------------------------------------------------------

%package -n     medulla-agent-relay
Summary:        Medulla 2 common files
Group:          System/Servers
BuildArch:      noarch

Requires(pre):  shadow-utils

Requires:       python3-netifaces
Requires:       python3-slixmpp
Requires:       python3-croniter
Requires:       python3-requests
Requires:       python3-inotify
Requires:       python3-dateutil
Requires:       python3-psutil
Requires:       python3-wakeonlan
Requires:       python3-cryptodome
Requires:       python3-cherrypy
Requires:       net-tools
Requires:       jq
Requires:       python3-distro
Requires:       python3-lmdb
Requires:       python3-xmltodict
Requires:       python3-netaddr

Obsoletes:     medulla-agent < 2.0.7
Provides:      medulla-agent = %version

Obsoletes:     pulseagent-plugins-relay < 2.0.7
Provides:      pulseagent-plugins-relay = %version

%description -n medulla-agent-relay
Medulla master agent substitute

%pre -n     medulla-agent-relay
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

%post -n medulla-agent-relay
if [ -f "/usr/lib/python3.5/site-packages/medulla_agent/BOOL_UPDATE_AGENT" ]; then
    rm -f /usr/lib/python3.5/site-packages/medulla_agent/BOOL_UPDATE_AGENT
fi

if systemctl -q is-enabled medulla-master-substitute-inventory ; then
    echo -n "Restarting medulla-master-substitute-inventory service..."
    systemctl restart medulla-master-substitute-inventory
    echo "..done"
fi

if systemctl -q is-enabled medulla-master-substitute-registration ; then
    echo -n "Restarting medulla-master-substitute-registration service..."
    systemctl restart medulla-master-substitute-registration
    echo "..done"
fi

if systemctl -q is-enabled medulla-master-substitute-assessor ; then
    echo -n "Restarting medulla-master-substitute-assessor service..."
    systemctl restart medulla-master-substitute-assessor
    echo "..done"
fi

if systemctl -q is-enabled medulla-master-substitute-deployment ; then
    echo -n "Restarting medulla-master-substitute-deployment service..."
    systemctl restart medulla-master-substitute-deployment
    echo "..done"
fi

if systemctl -q is-enabled medulla-master-substitute-subscription ; then
    echo -n "Restarting medulla-master-substitute-subscription service..."
    systemctl restart medulla-master-substitute-subscription
    echo "..done"
fi

if systemctl -q is-enabled medulla-master-substitute-logger ; then
    echo -n "Restarting medulla-master-substitute-logger service..."
    systemctl restart medulla-master-substitute-logger
    echo "..done"
fi

if systemctl -q is-enabled medulla-master-substitute-reconfigurator ; then
    echo -n "Restarting medulla-master-substitute-reconfigurator service..."
    systemctl restart medulla-master-substitute-reconfigurator
    echo "..done"
fi

if systemctl -q is-enabled medulla-master-substitute-monitoring ; then
    echo -n "Restarting medulla-master-substitute-monitoring service..."
    systemctl restart medulla-master-substitute-monitoring
    echo "..done"
fi

if systemctl -q is-enabled medulla-master-substitute-updates ; then
    echo -n "Restarting medulla-master-substitute-updates service..."
    systemctl restart medulla-master-substitute-updates
    echo "..done"
fi

%files -n medulla-agent-relay
%_prefix/lib/systemd/system/medulla-agent-relay.service
%_prefix/lib/systemd/system/pulse-package-watching.service
%dir %_sysconfdir/medulla-agent/
%_sysconfdir/logrotate.d/medulla-agent-relay
%config(noreplace) %_sysconfdir/medulla-agent/guacamoleconf.ini
%config(noreplace) %_sysconfdir/medulla-agent/downloadfile.ini
%config(noreplace) %_sysconfdir/medulla-agent/downloadfileexpert.ini
%config(noreplace) %_sysconfdir/medulla-agent/applicationdeploymentjson.ini
%config(noreplace) %_sysconfdir/medulla-agent/guacamole.ini
%config(noreplace) %_sysconfdir/medulla-agent/reverse_ssh_on.ini
%config(noreplace) %_sysconfdir/medulla-agent/wakeonlan.ini
%config(noreplace) %_sysconfdir/medulla-agent/relayconf.ini
%config(noreplace) %_sysconfdir/medulla-agent/package_watching.ini
%config(noreplace) %_sysconfdir/medulla-agent/manage_scheduler_relay.ini
%config(noreplace) %_sysconfdir/medulla-agent/start_relay.ini
%config(noreplace) %_sysconfdir/medulla-agent/ars___server_tcpip.ini
%_var/log/pulse
%dir %{python3_sitelib}/medulla_agent/
%{python3_sitelib}/medulla_agent/lib/
%{python3_sitelib}/medulla_agent/*.py*
%{python3_sitelib}/medulla_agent/script/
%{python3_sitelib}/medulla_agent/pluginsrelay/
%{python3_sitelib}/medulla_agent/pluginsmachine/
%{python3_sitelib}/medulla_agent/agentversion
%{python3_sitelib}/medulla_agent/descriptor_scheduler_relay/
%{python3_sitelib}/medulla_agent/descriptor_scheduler_machine/
%{python3_sitelib}/medulla_agent/__pycache__/

#--------------------------------------------------------------------

%package -n     medulla-master-substitute
Summary:        Medulla 2 common files
Group:          System/Servers
Requires:       python3-xmltodict
Requires:       jq
BuildArch:      noarch

%description -n medulla-master-substitute
Medulla master agent substitute

%post -n medulla-master-substitute
systemctl daemon-reload

%files -n medulla-master-substitute
%{python3_sitelib}/medulla_master_substitute/
%config(noreplace) %_sysconfdir/medulla-agent-substitute/
%_prefix/lib/systemd/system/medulla-master-substitute-inventory.service
%_prefix/lib/systemd/system/medulla-master-substitute-registration.service
%_prefix/lib/systemd/system/medulla-master-substitute-assessor.service
%_prefix/lib/systemd/system/medulla-master-substitute-subscription.service
%_prefix/lib/systemd/system/medulla-master-substitute-logger.service
%_prefix/lib/systemd/system/medulla-master-substitute-deployment.service
%_prefix/lib/systemd/system/medulla-master-substitute-reconfigurator.service
%_prefix/lib/systemd/system/medulla-master-substitute-monitoring.service
%_prefix/lib/systemd/system/medulla-master-substitute-master.service
%_prefix/lib/systemd/system/medulla-master-substitute-updates.service
%_var/lib/pulse2/script_monitoring/


#--------------------------------------------------------------------

%package -n pulse-agent-installers
Summary:    Files to create pulse windows installer
Group:      System/Servers

Requires:   medulla-agent-deps >= 1.8

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

#--------------------------------------------------------------------

%package -n medullamaster-agentplugins
Summary:    Console agent
Group:      System/Servers
Requires:   python3-netifaces
Requires:   python3-slixmpp

%description -n medullamaster-agentplugins
plugins for pulse xmppmaster

%files -n medullamaster-agentplugins
%_var/lib/pulse2/xmpp_baseplugin
%_var/lib/pulse2/xmpp_basepluginscheduler

#--------------------------------------------------------------------

%package -n pulseagent-plugins-relay
Summary:    Console agent
Group:      System/Servers
Requires:   python3-wakeonlan
Requires:   python3-netifaces
Requires:   python3-slixmpp
Requires:   lsof

%description -n pulseagent-plugins-relay
plugins for pulse xmppmaster

%files -n pulseagent-plugins-relay
%python3_sitelib/medulla_agent/pluginsrelay
%python3_sitelib/medulla_agent/descriptor_scheduler_relay

#--------------------------------------------------------------------

%prep
%setup -q

# Remove bundled egg-info
rm -rf %{tarname}.egg-info

%build
# Nothing to do

%install
mkdir -p %buildroot%{python3_sitelib}/medulla_agent
cp -fr medulla_agent/* %buildroot%{python3_sitelib}/medulla_agent
rm -fr %buildroot%{python3_sitelib}/medulla_agent/config
rm -fr %buildroot%{python3_sitelib}/medulla_agent/descriptor_scheduler_common
rm -fr %buildroot%{python3_sitelib}/medulla_agent/plugins_common
rm -fr %buildroot%{python3_sitelib}/medulla_agent/descriptor_scheduler_machine/scheduling_*.py
rm -fr %buildroot%{python3_sitelib}/medulla_agent/pluginsmachine/plugin_*.py
cp -fv medulla_agent/plugins_common/plugin_* %buildroot%{python3_sitelib}/medulla_agent/pluginsrelay
cp -fv medulla_agent/descriptor_scheduler_common/scheduling_*.py %buildroot%{python3_sitelib}/medulla_agent/descriptor_scheduler_relay/
chmod +x %buildroot%{python3_sitelib}/medulla_agent/agentxmpp.py
chmod +x %buildroot%{python3_sitelib}/medulla_agent/package_watching.py
chmod +x %buildroot%{python3_sitelib}/medulla_agent/launcher.py
mkdir -p %buildroot%_var/log/pulse/
mkdir -p %buildroot%_prefix/lib/systemd/system
mkdir -p %buildroot%_var/lib/pulse2/clients/config/
cp -fr medulla_agent/config/systemd/* %buildroot%_prefix/lib/systemd/system
cp -fv ./scripts_installer/lin/*.service %buildroot%_prefix/lib/systemd/system
rm -fv %buildroot%_prefix/lib/systemd/system/medulla-agent-machine.service
mkdir -p %buildroot%_var/lib/pulse2/xmpp_baseplugin
mkdir -p %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
cp -frv medulla_agent/plugins_common/plugin_* %buildroot%_var/lib/pulse2/xmpp_baseplugin
cp -frv medulla_agent/pluginsmachine/plugin_* %buildroot%_var/lib/pulse2/xmpp_baseplugin
cp -frv medulla_agent/pluginsrelay/plugin_* %buildroot%_var/lib/pulse2/xmpp_baseplugin
cp -fv  medulla_agent/descriptor_scheduler_common/scheduling_* %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler	
cp -fv  medulla_agent/descriptor_scheduler_machine/scheduling_* %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
cp -fv  medulla_agent/descriptor_scheduler_relay/scheduling_* %buildroot%_var/lib/pulse2/xmpp_basepluginscheduler
mkdir -p %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/guacamoleconf.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/downloadfile.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/downloadfileexpert.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/applicationdeploymentjson.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/guacamole.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/reverse_ssh_on.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/wakeonlan.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/relayconf.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/package_watching.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/manage_scheduler_relay.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/start_relay.ini %buildroot%_sysconfdir/medulla-agent
cp medulla_agent/config/ars___server_tcpip.ini %buildroot%_sysconfdir/medulla-agent
mkdir -p %buildroot%_sysconfdir/logrotate.d/
cp contrib/scripts/medulla-agent-relay.logrotate %buildroot%_sysconfdir/logrotate.d/medulla-agent-relay
mkdir -p %buildroot%{python3_sitelib}/medulla_master_substitute/
cp medulla_master_substitute/agentmastersubstitute.py %buildroot%{python3_sitelib}/medulla_master_substitute/
cp medulla_master_substitute/agentversion %buildroot%{python3_sitelib}/medulla_master_substitute/
cp -r medulla_master_substitute/bin/ %buildroot%{python3_sitelib}/medulla_master_substitute/
cp -r medulla_master_substitute/lib/  %buildroot%{python3_sitelib}/medulla_master_substitute/
cp -r medulla_master_substitute/pluginsmastersubstitute/ %buildroot%{python3_sitelib}/medulla_master_substitute/
cp -r medulla_master_substitute/script/ %buildroot%{python3_sitelib}/medulla_master_substitute/
mkdir -p %buildroot%{python3_sitelib}/medulla_master_substitute/sessiondeploysubstitute/
touch -p %buildroot%{python3_sitelib}/medulla_master_substitute/sessiondeploysubstitute/EMPTY
mkdir -p %buildroot%_sysconfdir/medulla-agent-substitute/
cp medulla_master_substitute/config/*.ini %buildroot%_sysconfdir/medulla-agent-substitute/
cp -fr medulla_master_substitute/config/systemd/* %buildroot%_prefix/lib/systemd/system
chmod +x %buildroot%{python3_sitelib}/medulla_master_substitute/agentmastersubstitute.py
# We create the installer part now
mkdir medulla-agent-%{version}
mkdir -p pulse-machine-plugins-%{version}/medulla_agent/pluginsmachine
mkdir -p pulse-machine-plugins-%{version}/medulla_agent/descriptor_scheduler_machine
cp -frv medulla_agent medulla-agent-%{version}/
cp -fv packaging/python/agent_setup.py medulla-agent-%{version}/setup.py
cp -fv packaging/python/machineplugins_setup.py pulse-machine-plugins-%{version}/setup.py
cp -fv packaging/python/LICENSE medulla-agent-%{version}
cp -fv packaging/python/README.md medulla-agent-%{version}
cp -fv packaging/python/MANIFEST.in medulla-agent-%{version}
cp -fv packaging/python/LICENSE pulse-machine-plugins-%{version}
cp -fv packaging/python/README.md pulse-machine-plugins-%{version}	
rm -fr medulla-agent-%{version}/medulla_agent/config
mv medulla-agent-%{version}/medulla_agent/plugins_common/plugin_*.py pulse-machine-plugins-%{version}/medulla_agent/pluginsmachine
mv medulla-agent-%{version}/medulla_agent/descriptor_scheduler_common/scheduling_*.py pulse-machine-plugins-%{version}/medulla_agent/descriptor_scheduler_machine
mv medulla-agent-%{version}/medulla_agent/pluginsmachine/plugin_*.py pulse-machine-plugins-%{version}/medulla_agent/pluginsmachine
mv medulla-agent-%{version}/medulla_agent/descriptor_scheduler_machine/scheduling_*.py pulse-machine-plugins-%{version}/medulla_agent/descriptor_scheduler_machine
rm -fr medulla-agent-%{version}/medulla_agent/descriptor_scheduler_common/
rm -fr medulla-agent-%{version}/medulla_agent/descriptor_scheduler_relay/scheduling_*.py
rm -fr medulla-agent-%{version}/medulla_agent/plugins_common/
rm -fr medulla-agent-%{version}/medulla_agent/pluginsrelay/plugin_*.py
tar czvf medulla-agent-%{version}.tar.gz medulla-agent-%{version}
rm -fr medulla-agent-%{version}
tar czvf pulse-machine-plugins-%{version}.tar.gz pulse-machine-plugins-%{version}
rm -fr pulse-machine-plugins-%{version}
mkdir -p %buildroot%_var/lib/pulse2/clients
mv  medulla-agent-%{version}.tar.gz %buildroot%_var/lib/pulse2/clients
mv  pulse-machine-plugins-%{version}.tar.gz %buildroot%_var/lib/pulse2/clients
GIT_SSL_NO_VERIFY=true git clone https://github.com/pulse-project/kiosk-interface.git
mv kiosk-interface kiosk-interface-%{kiosk_version}
tar czvf kiosk-interface-%{kiosk_version}.tar.gz kiosk-interface-%{kiosk_version}
rm -fr kiosk-interface-%{kiosk_version}
mv kiosk-interface-%{kiosk_version}.tar.gz %buildroot%_var/lib/pulse2/clients
mkdir -p %buildroot%_var/lib/pulse2/xmpp_baseremoteagent
cp -frv medulla_agent/* %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/
rm -frv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/config
rm -frv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/descriptor_scheduler_common
rm -frv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/plugins_common
rm -fv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/descriptor_scheduler_machine/scheduling_*.py
rm -fv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/pluginsmachine/plugin_*.py
rm -fv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/descriptor_scheduler_relay/scheduling_*.py
rm -fv %buildroot%_var/lib/pulse2/xmpp_baseremoteagent/pluginsrelay/plugin_*.py
mkdir -p %buildroot%_var/lib/pulse2/clients/config/
cp medulla_agent/config/agentconf.ini %buildroot%_var/lib/pulse2/clients/config/
cp medulla_agent/config/manage_scheduler_machine.ini %buildroot%_var/lib/pulse2/clients/config/
cp medulla_agent/config/inventory.ini %buildroot%_var/lib/pulse2/clients/config/
cp medulla_agent/config/start_machine.ini %buildroot%_var/lib/pulse2/clients/config/
cp medulla_agent/config/startupdate.ini %buildroot%_var/lib/pulse2/clients/config/
cp medulla_agent/config/updateopenssh.ini %buildroot%_var/lib/pulse2/clients/config/
cp medulla_agent/config/updatetightvnc.ini %buildroot%_var/lib/pulse2/clients/config/
cp medulla_agent/config/updatebackupclient.ini %buildroot%_var/lib/pulse2/clients/config/
cp medulla_agent/config/am___server_tcpip.ini %buildroot%_var/lib/pulse2/clients/config/
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
cp scripts_installer/mac/net.siveo.medulla_agent.plist %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/rbash %buildroot%_var/lib/pulse2/clients/mac
cp scripts_installer/mac/runpulseagent %buildroot%_var/lib/pulse2/clients/mac
mkdir -p %buildroot%_var/lib/pulse2/clients/win/libs
cp -fr scripts_installer/win/nsis_libs/* %buildroot%_var/lib/pulse2/clients/win/libs
mkdir -p %buildroot%_var/lib/pulse2/clients/win/artwork
cp -fr scripts_installer/win/artwork/* %buildroot%_var/lib/pulse2/clients/win/artwork
chmod +x %buildroot%_var/lib/pulse2/clients/*.sh
chmod +x %buildroot%_var/lib/pulse2/clients/generate-agent-package
cp medulla_agent/script/create-profile.ps1 %buildroot%_var/lib/pulse2/clients/win/
cp medulla_agent/script/remove-profile.ps1 %buildroot%_var/lib/pulse2/clients/win/
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
#cp medulla_agent/bin/pulse2_update_notification.py %buildroot%_var/lib/pulse2/clients/win/
#cp medulla_agent/bin/pulse2_update_notification.py %buildroot%_var/lib/pulse2/clients/lin/
#cp medulla_agent/bin/pulse2_update_notification.py %buildroot%_var/lib/pulse2/clients/mac/
cp medulla_agent/bin/RunMedullaKiosk.bat %buildroot%_var/lib/pulse2/clients/win/
