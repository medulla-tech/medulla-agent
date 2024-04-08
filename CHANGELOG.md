# Change Log

## [v3.1.0](unreleased)
- [FEATURE]  Create agentconfig.ini.tpl ( to fix broken agent )
- [FEATURE]  Create kiosk profiles based on AD groups
- [BUGFIX]   Fix creation of the img_agent (#397)

[Full Changelog](https://github.com/medulla-tech/medulla-agent/compare/v3.0.1...v3.1.0)

## [v3.0.2](unreleased)
- [FEATURE]  Update to Python 3.11.8
- [BUGFIX]   Fix the inventory Quick Action

[Full Changelog](https://github.com/medulla-tech/medulla-agent/compare/v3.0.1...v3.0.2)

## [v3.0.1](https://github.com/medulla-tech/medulla-agent/tree/v3.0.1) (2024-03-22)
- [FEATURE]  Install python in c:\Program Files\Python3
- [FEATURE]  Install Kiok interface by default now
- [BUGFIX]   Fix the exclusion of plugins from the installer
- [BUGFIX]   Fix displaying Agent details QA
- [BUGFIX]   Fix detection the arch in order to use the good OCS Agent
- [BUGFIX]   Fix the update notification windows, make the text fit the window
- [BUGFIX]   Fix the generation of the Kiosk package for python3 version of Medulla

[Full Changelog](https://github.com/medulla-tech/medulla-agent/compare/v3.0.0...v3.0.1)

## [v3.0.0](https://github.com/medulla-tech/medulla-agent/tree/v3.0.0) (2023-12-13)
- [FEATURE]  Python stack is now version 3.11
- [FEATURE]  Migrate from sleexmpp to slixmpp
- [FEATURE]  Add support for OpenSSH 9.4
- [FEATURE]  Add support for Tightvnc 2.8.81
- [FEATURE]  Add support for vim on Windows
- [FEATURE]  Add support for paexec
- [FEATURE]  Add support for Glpi Agent 1.5
- [FEATURE]  Remove the inventory agent, but handle it in the inventory substitute agent
- [FEATURE]  Add support for Glpi 10+
- [FEATURE]  Add certificate to use TLS connexion between server and client
- [BUGFIX]   Fix QA supports with new slixmpp lib

[Full Changelog](https://github.com/medulla-tech/medulla-agent/compare/v2.1.9...v3.0.0)

## [v2.1.9](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.1.9) (2023-04-14)
- [FEATURE] Rename start.ini into start_machine.ini or start_relay.ini to handle coexistence
- [FEATURE] Add monitoring feature to start to allow monitoring of medulla installation
- [FEATURE] Add CDN support: Support for integrity
- [FEATURE] Add kiosk plugin
- [FEATURE] Add rescue agent, to help when something broken active/running agent
- [FEATURE] Add Glpi 10.0 support
- [FEATURE] Add GLPI-Agent support
- [BUGFIX]  Fix GLPI 9.5 Support
- [BUGFIX]  Fix the way we configure OpenSSH in the plugin
- [BUGFIX]  Fix display of the Windows version in the computer page.
- [BUGFIX]  Fix backtraces in the packagewatching
- [BUGFIX]  Fix retrieving the SSH Key of the ARS.
- [BUGFIX]  Fix restarting stalled deployements.
- [BUGFIX]  Do not hide real errors into debugs but use error logger instead.
- [BUGFIX]  Fix issue where machines are wrongly reported as offline

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.1.7...v2.1.9)

## [v2.1.7](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.1.7) (2021-09-21)
- [BUGFIX]  Fix detecting IP address of the XMPP server when the agent starts.
- [BUGFIX]  Fix backtrace in the substitute registration when there is more
than on location.
- [BUGFIX]  Fix handling some accounts creation

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.1.6...v2.1.7)

## [v2.1.6](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.1.6) (2021-08-06)
- [FEATURE] Change some infos messages into debug
- [FEATURE] Document more functions
- [FEATURE] Convergences are now identified by their name + date
- [FEATURE] Add more error messages to help to find where are the problems. (
when we cannot contact a database ).
- [BUGFIX]  Fix backtrace during deployment
- [BUGFIX]  Fix detection of online/offline machine in the Glpi view
- [BUGFIX]  Fix escaping symbols to fix backtraces
- [BUGFIX]  Fix support of older SQLAlchey
- [BUGFIX]  Fix registry when there is no uuidsetup defined
- [BUGFIX]  Grant Rights for Admin on the ARS Cluster.
- [BUGFIX]  Only show setupuuid info message if showinfobool is enable
- [BUGFIX]  Fix a backtrace when we have a machine with an inventory but no uuid_serial_machine.
- [BUGFIX]  Fix glpi 9.2 support (add back missing functions)
- [BUGFIX]  Fix support of accentuated letters glpi <-> pulse
- [BUGFIX]  Fix glpi 9.5 support
- [BUGFIX]  Initialise listmodulemmc before use
- [BUGFIX]  Fix registering ARS
- [BUGFIX]  Uninstall python and reinstall it if we failed the python pip step
- [BUGFIX]  Change cluster_resources sql column size to 255

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.1.5...v2.1.6)

## [v2.1.5](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.1.5) (2021-04-19)
- [FEATURE] Add the support of OCS
- [BUGFIX]  Add robustness for pulseuser profile checking

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.1.4...v2.1.5)

## [v2.1.4](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.1.4) (2021-01-20)
- [FEATURE] Add of a parameter to force configuration in case of network change
- [BUGFIX]  Fix replicator.py for relay automatic updates
- [BUGFIX]  Fix a segfault in guacamoleconf

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.1.3...v2.1.4)

## [v2.1.3](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.1.3) (2020-12-01)

- [FEATURE]  Add plugin to install fileviewer
- [FEATURE]  Add Glpi 9.5 support
- [FEATURE]  Add Openssh update plugin
- [FEATURE]  Add Syncthing update plugin
- [FEATURE]  Add FusionInventory update plugin
- [FEATURE]  Add Pulse Network Notify update plugin
- [FEATURE]  Add Tighvnc update plugin
- [FEATURE]  Clean installer to install only pulse + python  (and deps)
- [FEATURE]  Fix creation of reverse ssh tunnel
- [FEATURE]  Add monitoring support
- [FEATURE]  Add updateuseraccount plugin to create windows pulseuser account
- [FEATURE]  Fix restarting Agentxmpp if a processus die
- [FEATURE]  Add log compression support on windows
- [FEATURE]  Fix finding hostname where domain is written in the /etc/hostname file
- [BUGFIX]   Fix systemd support
- [BUGFIX]   Change pulseuser home folder from /var/lib/pulse2 to /home/pulseuser
- [BUGFIX]   Fix syncthing support
- [BUGFIX]   Fix debugs to be more understandable
- [BUGFIX]   Fix GLPI 0.84 support

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.1.2...v2.1.3)

## [v2.1.2](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.1.2) (2020-09-07)

- [FEATURE]  Use FusionInventory 2.5.2

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.1.1...v2.1.2)

## [v2.1.1](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.1.1) (2020-07-27)

- [FEATURE]  Agents now use ifconfig.co webservice to find location
- [FEATURE]  Automatic inventories are now sent only if they have changed
- [FEATURE]  Guacamole operations are now linked to XMPP inventory instead of GLPI
- [FEATURE]  Update synthing version used to 1.6.1
- [FEATURE]  Add support for regular expressions for blacklisted mac addresses
- [FEATURE]  Agents autoupdate by relay servers is now the default method
- [FEATURE]  P2P deployment now uses separate syncthing instance
- [BUGFIX]   Fix running of fusion inventory
- [BUGFIX]   Fix reconfiguration of machines
- [BUGFIX]   Fix transfer rate limitation for deployments
- [BUGFIX]   Eliminate mac addresses that are blacklisted as soon as they are received
- [BUGFIX]   Fix deletion of pulse user profile in agent installer
- [BUGFIX]   Fix deletion of OpenSSH in agent installer
- [BUGFIX]   Fix macOS installer

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.1.0...v2.1.1)

## [v2.1.0](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.1.0) (2020-05-19)

- [FEATURE]  Quick deployment: new mode for small packages
- [FEATURE]  New reconf substitute to allow mass-reconfiguration of machine agents
- [FEATURE]  New user for transferring files from client machine to pulse main server
- [BUGFIX]   Improve installer when run in restricted powershell policies
- [BUGFIX]   Fix linux installer
- [BUGFIX]   Fix and improve configuration of remote desktop protocols

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.0.8...v2.1.0)

## [v2.0.8](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.0.8) (2020-04-28)

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.0.7...v2.0.8)

## [v2.0.7](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.0.7) (2020-04-09)

- [BUGFIX]   Improve the handling of errors in the installer
- [BUGFIX]   Auto-correct deployment errors that can be corrected
- [BUGFIX]   Fix agent errors linked to internal servers and named pipes
- [FEATURE]  Optimize the size of the installers
- [FEATURE]  Pulldirect is now default method if push fails

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.0.6...v2.0.7)

## [v2.0.6](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.0.6) (2020-03-25)

- [BUGFIX]   Review messages sent to the logger
- [BUGFIX]   Fix Agent Details quick action where the image is not generated
- [BUGFIX]   Fix Agent Details quick action where the image is not generated
- [FEATURE]  Allow autoupdate by relay servers instead of main pulse in multisite setups
- [FEATURE]  Define additional statuses for deployments
- [FEATURE]  Allow to have more debug information for specific machines only
- [FEATURE]  Define intervals for calculating fingerprints and reloading plugins

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.0.5...v2.0.6)

## [v2.0.5](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.0.5) (2020-02-27)

- [FEATURE]  Integration of logger and deployment substitutes
- [BUGFIX]   Fix sockets that are stuck in TIME_WAIT state
- [BUGFIX]   Force configuration of guacamole if no connection present

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.0.4...v2.0.5)

## [v2.0.4](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.0.4) (2020-02-17)

- [FEATURE]  Integration of assessor and registration substitutes

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.0.3...v2.0.4)

## [v2.0.3](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.0.3) (2019-12-19)

- [BUGFIX]  Fix problem where agent stops after cycling through the alternate
                        connections if no server is available
- [BUGFIX]  Fix agent configuration when Pulse server is not available when
                        configurator runs
- [BUGFIX]  Fixe error search last name user on windows

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.0.2...v2.0.3)

## [v2.0.2](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.0.2) (2019-12-03)

- Improve use of pulse/pulseuser for file transfert

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v2.0.1...v2.0.2)

## [v2.0.1](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.0.1) (2019-06-28)

- [Feature] Enable substitute agents by default
- [Feature] Allow to limite transfert rate when using syncthing
- [Feature] Add Glpi substitute support
- [Feature] Allow to use pullrsync without package server
- [BUGFIX]  Improve syncthing support and API
- [BUGFIX]  Fix default creation of syncthing config.xml file

## [v2.0.0](https://github.com/pulse-project/pulse-xmpp-agent/tree/v2.0.0) (2019-03-12)

- [FEATURE] Allow scp and rsync transfers in Pull mode
- [FEATURE] Peer deployment
- [FEATURE] Allow install of plugin if a specific version of client is met
- [FEATURE] Remove all deployments on restart of relay agent
- [BUGFIX]  Reconnect to XMPP server on lost connection
- [BUGFIX]  Check if all necessary python modules are installed before loading agent image
- [BUGFIX]  Use database connections pool to reduce load on database
- [BUGFIX]  Fix the release of resources after a deployment
- [BUGFIX]  Fix generation of random deployment session names

[Full Changelog](https://github.com/pulse-project/pulse-xmpp-agent/compare/v1.9.8...v2.0.0)

## [v1.9.8]

- [FEATURE] Push method (scp or rsync) can be configured in relay server
- [BUGFIX]  Fix cleaning of deployments which have been aborted
- [BUGFIX]  Fix detection of VNC configuration
- [BUGFIX]  Fix management of default directory in file transfer
- [BUGFIX]  Fix decoding of command string
- [BUGFIX]  Fix management of sessions
- [BUGFIX]  Fix alternative connection when a server of the cluster goes down
- [BUGFIX]  Make use of an external program for generating the filetree

## [v1.9.7]

- [FEATURE] Allow a deployment to be spooled in priority
- [FEATURE] Allow the use of a .local config file
- [BUGFIX]  Fix time in logs
- [BUGFIX]  Fix advanced deployment on groups
- [BUGFIX]  Fix VNC permissions via quick action

## [v1.9.6]

- [FEATURE] Autoupdate of agent
- [FEATURE] Force reconfiguration of agent
- [BUGFIX]  Fix editing configuration files in client machine
- [BUGFIX]  Fix detection of network changes

## [v1.9.5]

- [FEATURE] Addition of an inventory step after deployment
- [BUGFIX] Fix edition of config files
- [BUGFIX] Fix encoding for remote console
- [BUGFIX] Fix encoding for commands run on Windows

## [v1.9.3]

- [Bugfix] Fix backslash management for bat and ps1 scripts on Windows

## [v1.9.2]

- [Bugfix] Fix encoding of adorgbyuser

## [v1.9.1]

- [Bugfix] Fix encoding in remote shell
- [Bugfix] Fix detection of remote protocols in Linux
- [Bugfix] Add relayconf.ini.in in pulse-xmpp-agent package

## [v1.9.0]

- [Feature] Possibility to set options in agent config file from Pulse
- [Feature] Possibility to edit config file from Pulse
- [Bugfix] Fix detection of remote protocols using psutil
- [Bugfix] Check that AD is compliant before using it
- [Bugfix] Make sure the proper version of python is used on macOS
- [Bugfix] Fix shutdown command on macOS

## [v1.8.7]

- [Bugfix] Fix unzipping of files in grafcetdeploy
- [Bugfix] Fix detection of netmask for MacOS
- [Feature] Update scheduler plugins automatically

## [v1.8.6]


- Action for changing VNC parameters to toggle user approval request before connecting
- Fix reading of registry keys on Windows machines
- Improve scheduling of automatic inventories
- New actions for packaging

## [v1.8.5]

- Option to shutdown or reboot machine after deployment


