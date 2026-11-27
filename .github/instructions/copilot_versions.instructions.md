---
applyTo: "**"
---
# Target versions (Medulla agent)

Target platform: Debian 12.
Project license: GPL-3.0-or-later.

- Python 3.13

Rules:

- Write Python 3 only. Never use Python 2 syntax or libraries.
- Do not use features newer than the target version.
- Some files (for example `setup.py`) still declare older versions. Do not change them unless asked.
