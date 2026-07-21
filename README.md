# CYBERBLACK-OPS v2.1.0

Enterprise-grade CEH · OSINT · Pentesting Toolkit

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗      █████╗  ██████╗██╗  ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║     ███████║██║     █████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██║     ██╔══██║██║     ██╔═██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                               CYBERBLACK-OPS v2.1.0
```

CYBERBLACK-OPS is a compact, modular cybersecurity toolkit for reconnaissance, Wi-Fi testing, web application testing, exploitation, OSINT, packet analysis, post-exploitation, vulnerability assessment, and forensics. It provides a structured terminal UI with install status tracking, audit logging, a live network monitor, and safe command execution with confirmation gates.

**Warning:** Use only on targets for which you have explicit authorization. Unauthorized testing is illegal and unethical.

---

## Quickstart (Linux recommended)

### 1. Clone

```bash
git clone https://github.com/anonyy063/CYBERBLACK-OPS.git
cd CYBERBLACK-OPS
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install the package

```bash
pip install -e .
```

### 4. Run CyberBlack

```bash
cyberblack
```

Or equivalently:

```bash
python -m cyberblack
```

### 5. Browse categories, check install status, and run tools

Use the main menu to select a category (1-10), browse tools within it, view detailed flag/usage info, and run or install tools directly from the interface.

---

## Features

- **33 tools across 10 categories** — networking, Wi-Fi, password attacks, web testing, exploitation, OSINT, MITM, post-exploitation, vulnerability assessment, and forensics
- **Install status detection** — cached `which`-style checks with `is_installed()`
- **Safe command execution** — confirmation gate for free-form commands; trusted commands for installs and examples
- **Audit logging** — JSONL log at `~/.cyberblack/run_log.jsonl` with `log_execution()` / `read_recent()`
- **Live network monitor** — real-time per-interface bandwidth, active connections, listening ports, CPU/RAM
- **Rich terminal UI** — color-coded risk badges, status badges, syntax-highlighted tables via `rich`
- **YAML-driven data** — categories and tool definitions in `cyberblack/data/categories/*.yaml`

---

## Project structure

```
cyberblack/
├── __init__.py          # package marker
├── __main__.py          # python -m cyberblack entry
├── cli.py               # main menu loop and CLI entry point
├── models.py            # Tool, ToolCategory, FlagDoc, UsageExample, RiskLevel
├── registry.py          # ToolRegistry, load_registry(), is_installed()
├── runner.py            # run_trusted(), run_freeform(), ExecutionResult
├── util.py              # clear_screen(), local_ip(), fmt_bytes()
├── audit.py             # log_execution(), read_recent()
├── ui/
│   ├── banner.py        # ASCII banner + disclaimer
│   ├── components.py    # build_table(), build_panel(), status_badge()
│   ├── menus.py         # show_main_menu(), show_category_menu(), etc.
│   └── monitor.py       # live network monitor
└── data/
    └── categories/      # 10 YAML files, one per category
tests/
├── test_models.py
├── test_registry.py
└── test_runner.py
```

---

## Usage scenarios

- **Pre-engagement recon** — Browse network scanning tools (nmap, masscan, etc.) and run scans from the UI.
- **OSINT enrichment** — Use the OSINT category for whois, theHarvester, Sherlock, etc.
- **Wi-Fi testing** — aircrack-ng suite, reaver, pixiewps under the Wi-Fi category.
- **Vulnerability assessment** — OpenVAS, nikto, wpscan, SQLmap.
- **Live monitoring** — Start the network monitor from the main menu (option `N`).

---

## Requirements

- Python 3.11+
- Linux (most tools are Linux-only; the package itself can be installed on any OS)
- Dependencies installed automatically: `rich`, `psutil`, `pyyaml`

---

## Security & responsible use

- **Authorization required** — Never operate this tool against systems, domains, or networks without written permission.
- **Responsible disclosure** — If you discover a vulnerability, follow coordinated disclosure practices.

---

## Contributing

Send focused pull requests with tests. Maintain backwards compatibility for public interfaces.

## License

MIT — see [LICENSE](LICENSE)

## Contact

For security reports or responsible disclosure: open an issue or contact anonyy063@gmail.com
