#!/bin/bash
VERSION_XMPP_AGENT=5.6.3
VERSION_KIOSK_INTERFACE=2.1.2
BRANCH=master
CURDIR=$(pwd) # Should be medulla-agent root folder
PYTHON_VERSION=python3.13

create_package_agent() {
    cd "${CURDIR}"
    # Remove cached folder and archives
	rm -fr "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}"
	rm -fr "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}"
	rm -fr "${CURDIR}/build/kiosk-interface-${VERSION_KIOSK_INTERFACE}"

    rm -f "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}.tar.gz"
    rm -f "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}.tar.gz"
    rm -f "${CURDIR}/build/kiosk-interface-${VERSION_KIOSK_INTERFACE}.tar.gz"

    mkdir "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}"
    mkdir -p "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/pluginsmachine"
	mkdir -p "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/descriptor_scheduler_machine"

	cp -frv pulse_xmpp_agent "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/"

	cp -fv packaging/python/agent_setup.py "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/setup.py"
	cp -fv packaging/python/machineplugins_setup.py "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}/setup.py"
	cp -fv packaging/python/LICENSE "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}"
	cp -fv packaging/python/README.md "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}"
	cp -fv packaging/python/MANIFEST.in "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}"
	cp -fv packaging/python/LICENSE "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}"
	cp -fv packaging/python/README.md "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}"

	cp -fv packaging/pip/requirements.txt "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/requirements.txt"
	cp -fv packaging/pip/pyproject_pulse_xmpp_agent.toml "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pyproject.toml"
	cp -fv packaging/pip/requirements_plugins.txt "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}/requirements.txt"
	cp -fv packaging/pip/pyproject_pulse_machine_plugins.toml "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}/pyproject.toml"


	rm -fr "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/config"

	mv "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/plugins_common/plugin_*.py" "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/pluginsmachine"
	mv "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/descriptor_scheduler_common/scheduling_*.py" "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/descriptor_scheduler_machine"
	mv "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/pluginsmachine/plugin_*.py" "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/pluginsmachine"
	mv "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/descriptor_scheduler_machine/scheduling_*.py" "${CURDIR}/build/pulse-machine-plugins-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/descriptor_scheduler_machine"
	
    rm -fr "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/descriptor_scheduler_common/"
	rm -fr "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/descriptor_scheduler_relay/scheduling_*.py"
	rm -fr "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/plugins_common/"
	rm -fr "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}/pulse_xmpp_agent/pluginsrelay/plugin_*.py"

    cd "${CURDIR}/build"
	tar czvf pulse-xmpp-agent-${VERSION_XMPP_AGENT}.tar.gz pulse-xmpp-agent-${VERSION_XMPP_AGENT}
	tar czvf pulse-machine-plugins-${VERSION_XMPP_AGENT}.tar.gz pulse-machine-plugins-${VERSION_XMPP_AGENT}
	
    mkdir -p "${CURDIR}/debian/tmp/var/lib/pulse2/clients"
	cp -f pulse-xmpp-agent-${VERSION_XMPP_AGENT}.tar.gz "${CURDIR}/debian/tmp/var/lib/pulse2/clients"
	cp -f pulse-machine-plugins-${VERSION_XMPP_AGENT}.tar.gz "${CURDIR}/debian/tmp/var/lib/pulse2/clients"
	
    # Kiosk package
    GIT_SSL_NO_VERIFY=true git clone --branch ${BRANCH} https://github.com/medulla-tech/kiosk-interface.git "kiosk-interface-${VERSION_KIOSK_INTERFACE}"
	tar czvf kiosk-interface-${VERSION_KIOSK_INTERFACE}.tar.gz kiosk-interface-${VERSION_KIOSK_INTERFACE}
    cp -f kiosk-interface-${VERSION_KIOSK_INTERFACE}.tar.gz "${CURDIR}/debian/tmp/var/lib/pulse2/clients"

}

create_package_substitute() {
    cd "${CURDIR}"

    rm -fr "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}"
    rm -f "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}.tar.gz"

	mkdir -p "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}/pulse_xmpp_master_substitute"

    cp -frv pulse_xmpp_master_substitute "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}/"
	rm -fr "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}/pulse_xmpp_master_substitute/config"
	cp -fv packaging/python/substitute_setup.py "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}/setup.py"
	cp -fv packaging/python/LICENSE "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}"
	cp -fv packaging/python/README.md "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}"

	cp -fv packaging/pip/requirements_sub.txt "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}/requirements.txt"
	cp -fv packaging/pip/pyproject_pulse_xmpp_master_substitute.toml "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}/pyproject.toml"

    cd "${CURDIR}/build"
    tar czvf pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}.tar.gz pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}
}

prepare_services_substitute() {
	cd "${CURDIR}"
	mkdir -p "${CURDIR}/build/relay-sub-agent"
	cp -fv pulse_xmpp_master_substitute/config/systemd/*.service "${CURDIR}/build/relay-sub-agent/systemd"
	sed -i "s,PATH,/opt/medulla/bin/$PYTHON_VERSION /opt/medulla/lib/$PYTHON_VERSION/site-packages,g" "${CURDIR}"/build/relay-sub-agent/systemd/*.service
}

prepare_conf_substitute() {
	cd "${CURDIR}"
	mkdir -p "${CURDIR}/build/relay-sub-agent"
	cp -fv pulse_xmpp_master_substitute/config/*.ini "${CURDIR}/build/relay-sub-agent/conf"
}

prepare_certificates() {
	cd "${CURDIR}"
	return
	#cp "medulla-ca-chain.cert.pem" "${CURDIR}/build/relay-sub-agent"
	#cp "medulla-rootca.cert.pem" "${CURDIR}/build/relay-sub-agent"
}

prepare_install_folder() {
	cd "${CURDIR}"
	cp -fv "scripts_installer/lin/install-pulse-relay-sub-agent-linux.sh.in" "${CURDIR}/build/relay-sub-agent/Medulla-AgentRelay-linux-MINIMAL-latest.sh"
	sed -i "s,@@AGENT_VERSION@@,$VERSION_XMPP_AGENT,g" "${CURDIR}/build/relay-sub-agent/Medulla-AgentRelay-linux-MINIMAL-latest.sh"
	cp -fv "${CURDIR}/build/pulse-xmpp-agent-${VERSION_XMPP_AGENT}.tar.gz" "${CURDIR}/build/relay-sub-agent/pulse-xmpp-agent-${VERSION_XMPP_AGENT}.tar.gz"
	cp -fv "${CURDIR}/build/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}.tar.gz" "${CURDIR}/build/relay-sub-agent/pulse-xmpp-master-substitute-${VERSION_XMPP_AGENT}.tar.gz"
}

create_all_packages() {
    create_package_agent
    create_package_substitute
	prepare_services_substitute
	prepare_conf_substitute
	prepare_certificates
	prepare_install_folder
}

create_all_packages