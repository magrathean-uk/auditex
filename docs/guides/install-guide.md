# Install Auditex

This guide installs Auditex from PyPI with pipx, step by step, on Linux, macOS or Windows through WSL2. It is
written for an IT administrator: you do not need to know Python. Every command is shown; type it into a terminal
and press Enter. Lines that start with `#` in the boxes below are comments, not commands.

The short version, for a computer that already has Python 3.11, 3.12, 3.13 or 3.14 and pipx:

```bash
pipx install auditex
auditex --version
auditex doctor
```

The rest of this guide explains each step, what you should see, and what to do when something goes wrong.

## What you need

| Item | Requirement |
|---|---|
| Operating system | Linux (Ubuntu 22.04 or newer, Debian 12 or newer, Fedora, RHEL or Rocky Linux 9 or newer), macOS 13 or newer, or Windows 10 or 11 with WSL2. Native Windows (PowerShell or Command Prompt without WSL2) is not supported. |
| Python | 3.11, 3.12, 3.13 or 3.14. Step 2 installs it if you do not have it. |
| pipx | Any current version. Step 2 installs it. |
| Network | Access to `pypi.org` and `files.pythonhosted.org` while installing. The offline demo needs no network afterwards. |
| Disk | About 100 MB for Auditex and its libraries; run folders grow with tenant size. |
| Rights | Administrator (`sudo`) rights only to install Python and pipx with your system's package manager. Auditex itself installs into your own user account. |

Auditex is installed with pipx rather than plain `pip` because pipx gives Auditex its own private Python
environment and puts its commands (`auditex`, `auditex-mcp`, `azure-tenant-audit`) on your `PATH`. Nothing else on
the computer is changed, and removing Auditex later removes all of it.

## Step 1: open a terminal

- **macOS**: open Finder, then Applications, Utilities, Terminal.
- **Linux**: open your desktop's Terminal application, or connect over SSH.
- **Windows (WSL2)**: WSL2 runs a real Linux system inside Windows, and Auditex runs inside it. If you do not have
  WSL2 yet, open PowerShell as administrator (right-click Start, then Terminal (Admin)) and run:

  ```powershell
  wsl --install -d Ubuntu-24.04
  ```

  Restart Windows when asked. Ubuntu opens and asks you to choose a Linux user name and password; this account is
  separate from your Windows account. From then on, open Ubuntu from the Start menu and follow the Ubuntu steps
  below. Run every command in this guide inside the Ubuntu window, not in PowerShell.

## Step 2: install Python and pipx

First check whether you already have a recent Python:

```bash
python3 --version
```

You should see `Python 3.11`, `3.12`, `3.13` or `3.14` (for example `Python 3.12.3`). If you see an older version or
`command not found`, the commands below for your system install a suitable Python together with pipx.

### macOS

Install [Homebrew](https://brew.sh) first if you do not have it (the command is on its home page), then:

```bash
brew install python pipx
```

### Ubuntu 24.04 or newer, Debian 12 or newer (and WSL2 with Ubuntu 24.04)

```bash
sudo apt update
sudo apt install -y pipx
```

This also installs the system Python (3.12 on Ubuntu 24.04, 3.11 on Debian 12), which is recent enough.

### Fedora

```bash
sudo dnf install -y pipx
```

### RHEL, Rocky Linux or AlmaLinux 9

The default Python on these systems is 3.9, which is too old, so install Python 3.11 alongside it:

```bash
sudo dnf install -y python3.11 python3.11-pip
python3.11 -m pip install --user pipx
```

Then use `python3.11 -m pipx` wherever this guide says `pipx`, until Step 3 has put `pipx` on your `PATH`.

### Ubuntu 22.04

The default Python on Ubuntu 22.04 is 3.10, which is too old. Install pipx, then let pipx download a suitable
Python for Auditex in Step 4:

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

The `pipx` command is not on your `PATH` until you **close the terminal and open a new one**; do that now, before
the check below. (Until then, `python3 -m pipx` works in its place.)

### Check

```bash
pipx --version
```

Any version number (for example `1.7.1`) means pipx is ready.

## Step 3: put pipx's command folder on your PATH

pipx installs commands into `~/.local/bin`. Make sure your terminal looks there:

```bash
pipx ensurepath
```

Then **close the terminal and open a new one**, so the change takes effect. You only need to do this once per
computer.

## Step 4: install Auditex

```bash
pipx install auditex
```

pipx downloads Auditex and its libraries into a private environment. It ends with lines like these (the version
numbers will differ):

```text
  installed package auditex 2.0.0, installed using Python 3.12.3
  These apps are now available
    - auditex
    - auditex-mcp
    - azure-tenant-audit
```

On **Ubuntu 22.04** (or any system whose default Python is older than 3.11), ask pipx to fetch a suitable Python:

```bash
pipx install --python 3.12 --fetch-missing-python auditex
```

On RHEL or Rocky Linux 9 with Python 3.11 from Step 2:

```bash
pipx install --python python3.11 auditex
```

## Step 5: check the version

```bash
auditex --version
```

You should see the version you installed, for example:

```text
auditex 2.0.0
```

## Step 6: check the installation

```bash
auditex doctor
```

`auditex doctor` checks the local runtime and changes nothing. A working installation ends with `Core ready: yes`:

```text
System: Linux x86_64 (apt)
Python: supported Python 3.12.3 [/home/you/.local/share/pipx/venvs/auditex/bin/python]
Venv: supported [/home/you/.local/share/pipx/venvs/auditex]
pwsh: blocked (command_not_found)
Exchange module: blocked
Core ready: yes
Exchange ready: no (need pwsh, exchange_online_module)
Pwsh ready: no (need pwsh)
```

`Core ready: yes` is all you need for Microsoft 365 Graph collection, the offline demo and every report.
`Exchange ready` and `Pwsh ready` concern only the optional Exchange Online checks, which need PowerShell 7 and the
ExchangeOnlineManagement module; the [setup guide](setup-guide.md) explains when you need them. For a
machine-readable result (for example to keep with an audit record), run `auditex doctor --json`.

## Step 7 (optional): add extras

Some features need extra libraries, called extras. Install only the ones you need:

| Extra | Adds | Check after installing |
|---|---|---|
| `google` | Google Workspace audits (`auditex google ...`) | `auditex google doctor --json` |
| `mcp` | The local MCP server for AI assistants (`auditex-mcp`) | `auditex-mcp --help` |
| `local-answer` | The optional local language-model summary (`auditex explain`); see the [local answer guide](local-answer.md) | `auditex explain --help` |

Auditex is already installed from Step 4, so reinstall it with the extras. Name them in square brackets, separated
by commas, inside quotes, and add `--force`:

```bash
pipx install --force "auditex[google,mcp]"
```

List **every** extra you want to keep, because pipx installs exactly the extras named on its last install. Without
`--force`, pipx only reports that Auditex is already installed and adds nothing. If you installed with extra options
in Step 4, add the same options here: `--python 3.12 --fetch-missing-python` on Ubuntu 22.04, `--python python3.11`
on RHEL or Rocky Linux 9.

On a computer without Auditex yet, you can install it with the extras in one step instead of Step 4. Use the form
for your system, exactly as in Step 4:

```bash
pipx install "auditex[google,mcp]"
```

On **Ubuntu 22.04** (or any system whose default Python is older than 3.11):

```bash
pipx install --python 3.12 --fetch-missing-python "auditex[google,mcp]"
```

On RHEL or Rocky Linux 9 with Python 3.11 from Step 2:

```bash
pipx install --python python3.11 "auditex[google,mcp]"
```

The `local-answer` extra compiles llama.cpp while it installs, so it needs CMake and a C and C++ compiler first
(`xcode-select --install` and `brew install cmake` on macOS; `sudo apt install -y build-essential cmake` on Ubuntu
and Debian). Its language model is downloaded on first use, not at install time.

## Step 8: a first offline run

Auditex writes its run folders into the folder you run it from, so make a working folder first and move into it:

```bash
mkdir -p ~/auditex-work
cd ~/auditex-work
```

Run the demo. It replays a fictional company offline, contacts no tenant and needs no credentials:

```bash
auditex demo --no-pause
```

It walks through nine steps (access planning, findings, evidence, attack paths, a checksum-verified customer
pack) and finishes with `Open: file:///.../outputs/demo/explorer.html`. Then make a plain offline run from the built-in
sample:

```bash
auditex run --offline --tenant-name demo
```

It ends with `INFO: Offline sample written to audit-output/demo-run_<date>_<time>`.

To see the results, list the folders and open the HTML explorer in a browser:

```bash
ls outputs/demo
open outputs/demo/explorer.html        # macOS
xdg-open outputs/demo/explorer.html    # Linux desktop
explorer.exe "$(wslpath -w outputs/demo/explorer.html)"   # WSL2: opens it in Windows
```

When the demo has run, your installation is complete. The [setup guide](setup-guide.md) and
[reader app permissions](reader-app-permissions.md) take you to your first real tenant audit, and the
[product manual](product-manual.md) covers every workflow.

## Where run folders go

Every command writes below the current folder unless you pass `--out`:

| Command | Default folder |
|---|---|
| `auditex demo` | `outputs/demo` |
| `auditex run` (Microsoft 365) | `audit-output` |
| `auditex google run` | `outputs/google` |
| `auditex guided-run` | `outputs/guided` |
| `auditex probe live` | `outputs/probes` |

A run folder from a real tenant holds personal data about its users (names, addresses, sign-in records). Keep run
folders on an encrypted disk, in a folder only you can read, and delete them when the engagement ends; see the
[security and privacy model](../reference/security-privacy.md). Auditex never uploads them anywhere.

On WSL2, keep your working folder inside Linux (under `~`, as above), not on the Windows drive under `/mnt/c`:
Auditex sets owner-only permissions on its private files, and the Windows drive does not keep them.

## Upgrade

```bash
pipx upgrade auditex
auditex --version
```

`pipx upgrade` keeps the extras you installed. The new version number confirms the upgrade. Run folders from an
older version stay readable; read the [changelog](https://github.com/magrathean-uk/auditex/blob/main/CHANGELOG.md)
for what changed.

## Uninstall

```bash
pipx uninstall auditex
```

This removes Auditex and its private environment. Your run folders are not touched: delete them yourself when you
no longer need them. If you used the `local-answer` extra, delete its downloaded models too. They are in
`~/Library/Caches/auditex/models` on macOS and `~/.cache/auditex/models` on Linux and WSL2 (or
`$XDG_CACHE_HOME/auditex/models` when that is set), unless `AUDITEX_MODEL_DIR` named another folder:

```bash
rm -rf ~/Library/Caches/auditex/models   # macOS
rm -rf ~/.cache/auditex/models           # Linux and WSL2
```

## Troubleshooting

### `auditex: command not found`

The folder pipx installs into is not on your `PATH` yet. Run `pipx ensurepath`, close the terminal and open a new
one. `pipx list` shows whether Auditex is installed; if it is not listed, repeat Step 4.

### `pipx: command not found`

pipx is not installed, or (after a `pip install --user pipx`) its folder is not on your `PATH` yet. Repeat Step 2,
then run `python3 -m pipx ensurepath` and open a new terminal.

### `No matching distribution found for auditex` or `requires a different Python`

pipx is using a Python older than 3.11. Install with a newer one, as in Step 4:

```bash
pipx install --python 3.12 --fetch-missing-python auditex
```

Or, if Auditex is already installed with the wrong Python: `pipx reinstall --python python3.12 auditex`.

### `error: externally-managed-environment`

You ran `pip install auditex` instead of `pipx install auditex`. Recent Linux and macOS systems protect their own
Python from `pip`. Use pipx as in Step 4.

### Installing behind a proxy or without direct internet access

Set the proxy for the install command, for example:

```bash
HTTPS_PROXY=http://proxy.example.com:8080 pipx install auditex
```

If PyPI is mirrored internally, add `--index-url https://your-mirror/simple`.

### `Core ready: no`

`auditex doctor` names what is missing. Run `auditex doctor --json` and look at `readiness.core_missing`. A broken
install is usually fixed by `pipx reinstall auditex`.

### The `local-answer` extra fails to install

The error mentions CMake or a compiler. Install them (Step 7), then repeat the install command with `--force`.

### Native Windows

Auditex does not run in Windows PowerShell or Command Prompt. Install WSL2 (Step 1) and run Auditex inside Ubuntu.

More failures, including sign-in and permission problems during an audit, are in the
[troubleshooting guide](troubleshooting.md).

## Installing from source (contributors)

To change Auditex itself, or to run its test suite, install from a source checkout instead: see
"Install from source (contributors)" in the [README](../../README.md) and the
[runbook](../development/runbook.md).
