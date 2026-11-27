---
applyTo: "**"
---
# Repository architecture: medulla-agent

Python only. No PHP.

| Path | Content |
|---|---|
| `pulse_xmpp_agent/` | The agent: `agentxmpp.py`, `launcher.py`, `lib/`, `config/` |
| `pulse_xmpp_agent/pluginsmachine/` | Plugins for the machine agent |
| `pulse_xmpp_agent/pluginsrelay/` | Plugins for the relay agent |
| `pulse_xmpp_agent/plugins_common/` | Plugins shared by agents |
| `pulse_xmpp_agent/descriptor_scheduler_*/` | Schedulers (`scheduling_*.py`) per agent type |
| `pulse_xmpp_master_substitute/` | Server-side substitute agent, with its own `lib/`, `config/`, plugins and schedulers |
| `scripts_installer/` | Agent package generation and installers (`lin`, `mac`, `win`) |
| `packaging/`, `debian/` | Packaging |
| `contrib/`, `test/` | Auxiliary resources and tests |

Plugin conventions:

- A plugin is a file `plugin_<name>.py`.
- It declares `plugin = {"VERSION": ..., "NAME": ..., "TYPE": ...}`.
- Its entry point is `action(xmppobject, action, sessionid, data, message, dataerreur)`.

Rules:

- Put a plugin in the directory of the agent type that runs it.
- Never add data from a real infrastructure (host names, addresses, accounts) to the repository.
- Installed agents run from a `site-packages` path, which can differ from the repository layout.
