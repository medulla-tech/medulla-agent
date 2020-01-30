%define tarname		pulse-xmpp-agent
%define git                    SHA
%define use_git         1

Summary:	Pulse XMPP Agent
Name:		pulse-xmpp-agent
Version:	2.0.4
%if ! %use_git
Release:        1%{?dist}
%else
Release:        0.%git.1%{?dist}
%endif

Source0:        %name-%version.tar.gz
License:	MIT

Group:		Development/Python
Url:		http://www.siveo.net
BuildArch:	noarch
BuildRequires:	python-setuptools
BuildRequires:	python-sphinx

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

%post 
systemctl daemon-reload

%files
%_prefix/lib/systemd/system/pulse-xmpp-agent-log.service  
%_prefix/lib/systemd/system/pulse-xmpp-agent-machine.service  
%_prefix/lib/systemd/system/pulse-xmpp-agent-relay.service
%_prefix/lib/systemd/system/pulse-package-watching.service
%_sysconfdir/pulse-xmpp-agent
%_var/lib/pulse2/clients/config/*
%_var/log/pulse
%{python2_sitelib}/pulse_xmpp_agent
%{python2_sitelib}/pulse_xmpp_agent-%{version}-py%{python2_version}.egg-info

#--------------------------------------------------------------------

%package -n     pulse-xmpp-master-substitute
Summary:        Pulse 2 common files
Group:          System/Servers


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

%prep
%setup -q

# Remove bundled egg-info
rm -rf %{tarname}.egg-info

%build
%py2_build

%install
%py2_install
mkdir -p %buildroot%_var/log/pulse
mkdir -p %buildroot%_prefix/lib/systemd/system/
cp pulse_xmpp_agent/config/systemd/* %buildroot%_prefix/lib/systemd/system/

mkdir -p %buildroot%_sysconfdir/pulse-xmpp-agent/

chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/agentxmpp.py
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/pulse-xmpp-agent-log.py
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_agent/package_watching.py

mkdir -p %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/*ini.in %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/*ini %buildroot%_var/lib/pulse2/clients/config/
rm -fv %buildroot%_var//lib/pulse2/clients/config/agentconf.ini.in

mkdir -p %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp pulse_xmpp_master_substitute/agentmastersubstitute.py %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp pulse_xmpp_master_substitute/agentversion %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/bin/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/lib/  %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/pluginsmastersubstitute/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/
cp -r pulse_xmpp_master_substitute/script/ %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/

mkdir -p %buildroot%_sysconfdir/pulse-xmpp-agent-substitute/
cp pulse_xmpp_master_substitute/config/*.ini %buildroot%_sysconfdir/pulse-xmpp-agent-substitute/

cp pulse_xmpp_master_substitute/config/systemd/* %buildroot%_prefix/lib/systemd/system/
chmod +x %buildroot%{python2_sitelib}/pulse_xmpp_master_substitute/agentmastersubstitute.py
