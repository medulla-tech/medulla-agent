%define tarname		pulse-xmpp-agent
%define git                    SHA
%define use_git         1

Summary:	Pulse XMPP Agent
Name:		pulse-xmpp-agent
Version:	1.9.7
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

%description
Pulse XMPP Agent

%files
%_prefix/lib/systemd/system/*
%_sysconfdir/pulse-xmpp-agent
%_var/lib/pulse2/clients/config/*
%_var/log/pulse
%{python2_sitelib}/pulse_xmpp_agent
%{python2_sitelib}/pulse_xmpp_agent-%{version}-py%{python2_version}.egg-info

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

mkdir -p %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/*ini.in %buildroot%_var/lib/pulse2/clients/config/
cp pulse_xmpp_agent/config/*ini %buildroot%_var/lib/pulse2/clients/config/
