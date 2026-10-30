# DroidReaver

[![CI](https://github.com/Codeblin/droidreaver/actions/workflows/ci.yml/badge.svg)](https://github.com/Codeblin/droidreaver/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md)
[![Security policy](https://img.shields.io/badge/security-policy-green)](SECURITY.md)

> Previously known as DexMachina. See [MIGRATING.md](MIGRATING.md) if you are
> updating old installs, scripts, or workspace config.

**Android pentest environment manager** — install, sync, diagnose, and repair your entire mobile security toolkit from one CLI.

DroidReaver is evolving from a tool manager into a full **Android penetration environment**: one command to get adb, frida, jadx, apktool, and the rest of your kit installed, version-locked, and working together. It solves dependency hell — tools like `objection`, `r2frida`, and `frida-tools` all require the exact same `frida` version, and `apktool` needs a compatible JDK.

## Why DroidReaver

Most Android pentest setups grow from shell history, old notes, and a handful of one-off install scripts. DroidReaver turns that into a repo-local, reproducible environment: curated profiles, version pins, a lockfile, Frida runtime isolation, device readiness checks, and `doctor`/`fix` when the setup drifts.

It is not a replacement for MobSF, Corellium, Burp, or manual reverse-engineering judgment. It is the glue layer that gets a consistent workstation and rooted emulator/device ready faster than rebuilding the same adb/frida/objection/jadx setup for every engagement.

## Trust and Support

- Trust model: [THREAT_MODEL.md](THREAT_MODEL.md)
- Vulnerability reporting: [SECURITY.md](SECURITY.md)
- Contributing and adding tools: [CONTRIBUTING.md](CONTRIBUTING.md)
- Rename/migration guide: [MIGRATING.md](MIGRATING.md)
- Release process: [docs/RELEASE.md](docs/RELEASE.md)
- Branch protection checklist: [.github/BRANCH_PROTECTION.md](.github/BRANCH_PROTECTION.md)
- Release history: [CHANGELOG.md](CHANGELOG.md)

### Support matrix

| Host | Status | Notes |
| --- | --- | --- |
| Ubuntu/Debian Linux | Supported in CI | Primary development target; `apt` helpers expect Debian-style systems. |
| macOS Intel/Apple Silicon | Supported in CI | Homebrew-backed tools require `brew`. |
| Windows native | Unit-tested in CI | Core CLI paths are tested; some upstream tools have limited Windows support. |
| WSL2 | Not officially supported yet | Often works for host-only commands, but USB/emulator workflows need manual validation. |

### Known good device setups

| Setup | Status |
| --- | --- |
| Stock AVD | CI smoke-tested for adb/emulator basics |
| Rooted AVD | CI integration job boots an AVD and runs `device ready` + `frida-ps -U` |
| Genymotion | Expected to work, needs published validation |
| Corellium | Expected to work, needs published validation |

## Install

### Recommended: pipx

`pipx` installs DroidReaver in an isolated environment and exposes the
`droidreaver` command on your shell `PATH`.

```bash
# Kali/Debian/Ubuntu
sudo apt update
sudo apt install -y pipx
pipx ensurepath
pipx install droidreaver
```

On other Python installs where `pipx` is not packaged by the OS:

```bash
python -m pip install --user pipx
python -m pipx ensurepath
python -m pipx install droidreaver
```

Restart your terminal, then verify:

```bash
droidreaver --help
```

### PyPI with pip

```bash
python -m pip install droidreaver
```

On Kali, Debian 12+, Ubuntu 23.04+, and other PEP 668 distributions, system
Python may reject this with `externally-managed-environment`. Use `pipx`
instead, or install inside a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install droidreaver
droidreaver --help
```

Avoid `--break-system-packages` unless you intentionally want to modify the OS
Python environment.

If the install succeeds but `droidreaver` is not found, your Python scripts
directory is not on `PATH`. You can still run DroidReaver as a module:

```bash
python -m droidreaver --help
```

Or add the scripts directory printed by pip to your shell `PATH`. Common fixes:

```bash
# Linux/macOS user installs
python -m pip install --user droidreaver
export PATH="$HOME/.local/bin:$PATH"

# Windows PowerShell user installs
py -m pip install --user droidreaver
$env:PATH = "$env:APPDATA\Python\Python311\Scripts;$env:PATH"
```

On Windows, the exact `Python311` part depends on your Python version. If you
use the Python launcher, this always works even when the console script is not
on `PATH`:

```powershell
py -m droidreaver --help
```

### From GitHub

Install the latest `master` directly:

```bash
python -m pip install "git+https://github.com/Codeblin/DroidReaver.git"
```

Install a specific release tag:

```bash
python -m pip install "git+https://github.com/Codeblin/DroidReaver.git@v0.1.0"
```

### Developer install

```bash
git clone https://github.com/Codeblin/droidreaver.git
cd droidreaver
python -m pip install -e ".[dev]"
```

Run via the installed entrypoint or as a module:

```bash
droidreaver --help          # full ASCII banner + commands
droidreaver status          # compact banner + tool table
python -m droidreaver doctor
```

Set `DROIDREAVER_NO_BANNER=1` or pass `--no-banner` to suppress the ASCII art (useful for scripts/CI).

## Use it as a self-contained pentest environment (recommended)

Turn any repo into a portable Android pentest kit. Tools are downloaded into
`./.droidreaver/tools/`, version-locked, and added to your `PATH` on demand —
the heavy binaries stay **gitignored**, while the config and lockfile are
committed for reproducibility.

```bash
cd my-engagement-repo

droidreaver init                 # create droidreaver.toml + .gitignore + .droidreaver/tools
droidreaver up                   # install the profile + set up frida (one command)
droidreaver console              # interactive pentest REPL (recommended)
droidreaver shell                # …or a raw subshell with every tool on PATH
```

Inside `droidreaver shell`, tools like `jadx`, `apktool`, `objection`, and
`frida` are directly on your `PATH`. Type `exit` to leave.

If `doctor` or `fix` reports that a managed tool is installed but not on your
shell `PATH`, use DroidReaver's managed environment instead of editing global
shell startup files:

```bash
droidreaver shell
# or:
eval "$(droidreaver env)"
```

## Pentest a rooted emulator — full walkthrough

Assuming a rooted emulator/device is running with USB debugging (e.g. a
Genymotion / rooted AVD / Corellium instance, visible via `adb devices`):

```bash
# 0) one-time: build the dynamic-analysis kit (adb, frida, objection, …)
droidreaver up --profile dynamic

# 1) drop into the interactive console
droidreaver console
```

Then drive the engagement from the **DroidReaver console**:

```text
droidreaver [no-device | no-target]> devices          # auto-selects a single device
droidreaver [emulator-5554 | no-target]> ready        # push + start frida-server
droidreaver [emulator-5554 | no-target]> apps owasp   # find your target (filter)
droidreaver [emulator-5554 | no-target]> target com.example.app
droidreaver [emulator-5554 | com.example.app]> status # device + frida + target summary
droidreaver [emulator-5554 | com.example.app]> proxy 10.0.2.2:8080   # route HTTPS to Burp
droidreaver [emulator-5554 | com.example.app]> hook   # SSL pinning + root bypass (spawn)
droidreaver [emulator-5554 | com.example.app]> objection             # interactive explorer
droidreaver [emulator-5554 | com.example.app]> logcat com.example.app   # watch logs
droidreaver [emulator-5554 | com.example.app]> exit
```

The console keeps **live session state** (selected device + target app), so you
don't retype serials/packages. Every verb maps to the same engines the flat
CLI uses (`device ready`, `bypass`, `objection`, …) — just faster to chain.

### Console commands

| Verb | Description |
|------|-------------|
| `devices` / `use <serial>` | List devices / select the active one |
| `apps [filter]` | List installed apps (running ones marked) |
| `target <package>` | Set the app under test (accepts substrings) |
| `status` | Device + frida runtime + frida-server + target |
| `ready` | Push & start frida-server matching local frida |
| `hook [--spawn]` / `bypass [ssl\|root\|all] [--spawn]` | Attach SSL/root bypass to a running target; optionally spawn |
| `objection [args]` | Open Objection's explorer on the target |
| `proxy <host:port>` / `proxy off` | Set/clear the device global HTTP proxy |
| `logcat [filter]` | Stream device logs |
| `screenshot [file.png]` | Capture the screen to a local PNG |
| `adb <args>` / `adbshell` | Run adb / open an interactive adb shell |
| `pull` / `push` | Copy files off/onto the device |
| `ps` / `run <tool> [args]` | List processes / run any DroidReaver tool |
| `clear` · `help` · `exit` | Housekeeping |

Reproduce the exact kit on another machine:

```bash
droidreaver lock                 # write droidreaver.lock.toml (commit this)
# … teammate clones the repo …
droidreaver restore              # install the locked tools + frida runtime
```

## Quick Start

```bash
# One-command environment (auto-inits a repo-local workspace inside a git repo)
droidreaver up --profile dynamic

# See / inspect profiles
droidreaver profile list
droidreaver profile show static

# Drive an engagement interactively
droidreaver console              # pentest REPL with live device + target state

# Put every installed tool on PATH
droidreaver shell                # subshell (easiest)
droidreaver env                  # or print the PATH snippet for your shell

# Get a single tool, downloaded + on PATH + verified
droidreaver get jadx

# Get a device frida-ready in one shot (runtime + push-server + verify)
droidreaver device ready

# Check what's installed vs latest (use --offline to skip network)
droidreaver status --offline

# Diagnose / auto-repair
droidreaver doctor
droidreaver fix --bootstrap
```

### When to run `up`

Run `droidreaver up` when creating an environment, after cloning an engagement
workspace, or after changing its profile, pins, or lockfile. It is safe to run
again: tools and Frida environments that already satisfy the configuration are
skipped. Use `droidreaver update` for upgrades and `--force` only when you
intentionally want a reinstall.

For a normal daily pentest session, you usually only need:

```bash
droidreaver device ready          # reconnect/restart the matching frida-server
droidreaver console               # resume device + target workflow
```

## Commands

### Get started

| Command | Description |
|---------|-------------|
| `droidreaver init [--profile NAME] [--force]` | Create a repo-local workspace (config + `.gitignore` + `.droidreaver/tools`) |
| `droidreaver up [--profile NAME] [--no-frida] [--yes]` | Build the environment: install a profile + set up frida + write lockfile |
| `droidreaver console [--device SERIAL]` | Interactive pentest REPL with live device + target state |
| `droidreaver shell` | Open a subshell with every installed tool on `PATH` |
| `droidreaver profile list` / `show <name>` | List profiles or inspect a profile's tools |
| `droidreaver lock` | Write `droidreaver.lock.toml` from the current kit |
| `droidreaver restore [--yes]` | Install tools/frida exactly as recorded in the lockfile |

### Environment

| Command | Description |
|---------|-------------|
| `droidreaver status [--category NAME] [--offline]` | Table of installed vs latest versions |
| `droidreaver install <tool> [--version X.Y.Z] [--force]` | Install tool + dependencies |
| `droidreaver get <tool>` | Install a tool, put it on `PATH`, and verify it's runnable |
| `droidreaver install --all` | Install entire registry (topological order) |
| `droidreaver update [tool] [--all] [--force]` | Update to latest; pin groups update atomically |
| `droidreaver pin <tool> <version>` | Lock tool/pin-group version in config |
| `droidreaver unpin <tool>` | Remove version lock |
| `droidreaver env [--frida-only]` | Print PATH setup for all tools (or just the frida venv) |
| `droidreaver doctor` | Environment health report |
| `droidreaver fix [--dry-run] [--yes] [--bootstrap] [--aggressive]` | Diagnose and auto-repair issues |

### Device & arsenal

| Command | Description |
|---------|-------------|
| `droidreaver device list` | List connected ADB devices |
| `droidreaver device ready [--device SERIAL]` | Ensure frida runtime + push frida-server + verify with `frida-ps -U` |
| `droidreaver push-server [--device SERIAL] [--no-start]` | Push frida-server matching local frida |
| `droidreaver info [tool]` | Tool catalog, or detail card for one tool |
| `droidreaver arsenal` | List runnable tool CLIs (ready / missing) |
| `droidreaver run <tool> [args…]` | Run a tool via explicit dispatch |
| `droidreaver <tool> [args…]` | Direct dispatch (e.g. `droidreaver frida -U`) |
| `droidreaver config` | Show `droidreaver.toml` |
| `droidreaver config set <key> <value>` | Update a setting |

## Profiles

Profiles are curated tool bundles for one-command setup with `droidreaver up --profile NAME`:

| Profile | Tools |
|---------|-------|
| `minimal` | adb, frida, frida-tools |
| `dynamic` | frida stack, objection, r2frida, medusa |
| `static` | jadx, apktool, smali/baksmali, dex2jar, enjarify |
| `traffic` | mitmproxy, apk-mitm |
| `scanners` | MobSF, nuclei, drozer |
| `full` | everything auto-installable in the registry |

## Repo-local layout

`droidreaver init` produces a portable, reproducible workspace:

```text
my-repo/
├── droidreaver.toml         # committed — settings + profile + pins
├── droidreaver.lock.toml    # committed — exact installed versions (droidreaver lock)
├── .gitignore              # auto-updated to ignore downloaded tools
└── .droidreaver/
    ├── tools/              # downloaded CLIs/jars (gitignored)
    └── cache/              # PyPI/GitHub cache (gitignored)
```

Frida runtimes live in per-version venvs under `~/.droidreaver/venvs/` (machine-specific,
recreated by `droidreaver use` / `droidreaver restore`), so they're never committed.

## Configuration

`~/.droidreaver/droidreaver.toml` (or `./droidreaver.toml` in the project directory):

```toml
[settings]
adb_path = "adb"
java_path = "java"
install_dir = "~/.droidreaver/tools"
auto_push_frida_server = false

[pins]
frida = "16.1.4"   # pins the entire frida group

[ignored]
tools = ["ghidra", "wireshark"]
```

### Frida pin group (important)

The **frida runtime** (pip package `frida`) uses the version you care about for device hooks — e.g. `17.11.0`.

**frida-tools** and **objection** have **their own** pip version numbers (e.g. `14.9.0`, `1.12.5`) but must be compatible with the frida runtime. DroidReaver never installs `frida-tools==17.11.0` — that was the old bug.

| Command | What it does |
|---------|----------------|
| `droidreaver use 17.11.0` | **nvm-style** — create/select isolated venv for this runtime |
| `droidreaver use latest` | Use latest frida release |
| `droidreaver sync frida` | Align global pip: exact frida + upgrade companions |
| `droidreaver pin frida 17.11.0` | Save preference in config (then `use` or `sync`) |
| `droidreaver versions frida` | Show active, pinned, installed, PyPI releases |
| `droidreaver env` | Print `PATH` snippet for active venv |

After `droidreaver use X`, run the `droidreaver env` output in your shell, then `droidreaver push-server`.

### Arsenal — run tools through DroidReaver

Tools with a CLI are registered as native commands:

```bash
droidreaver arsenal              # ready vs missing
droidreaver frida --version
droidreaver frida-ps -U
droidreaver objection explore
droidreaver jadx --help
droidreaver run mitmproxy        # explicit form
```

Resolution order: **active frida venv** → `~/.droidreaver/tools/*/bin` → system `PATH`.

## Tool Categories

- **Dynamic Analysis** — frida, objection, r2frida, medusa
- **Static Analysis** — jadx, apktool, smali, radare2, ghidra (manual)
- **Traffic Interception** — mitmproxy, apk-mitm, Burp (manual)
- **Device & ADB** — adb, scrcpy, pidcat, androguard
- **APK Manipulation** — uber-apk-signer, apksigner (manual)
- **Automated Scanners** — MobSF, drozer, nuclei
- **Data & Storage** — binwalk, trufflehog, gitleaks
- **Network** — nmap, tcpdump, wireshark (manual)

Manual-only tools appear in `status` and `doctor` with install instructions but are not auto-installed.

## `droidreaver fix`

Three-phase repair flow: **diagnose → plan → apply → re-check**.

**Safe by default** (from `doctor` findings):

| Issue | Action |
|-------|--------|
| Frida pin group mismatch | Sync or reinstall entire group (respects `[pins]`) |
| frida-server not running | `push-server` |
| adb missing | Install platform-tools |
| Broken pip/github install | Reinstall tool |

**Flags:**

| Flag | Effect |
|------|--------|
| `--dry-run` | Show plan only |
| `--yes` / `-y` | Skip confirmation |
| `--bootstrap` | Install missing core env tools: adb, frida, jadx, apktool, mitmproxy, … |
| `--aggressive` | Also update all outdated registry tools |
| `--only frida,server` | Limit to categories |

Manual steps (Python upgrade, Java, Node.js, no device connected) are listed but never auto-applied.

### Impact levels

Each fix shows an **Impact** column — how disruptive the change is, **not** a security rating.

| Level | Meaning |
|-------|---------|
| **Low impact** | One tool or device; easily reversed (install adb, push frida-server, reinstall one tool) |
| **Medium impact** | Multiple packages or version bumps together (sync frida pin group, `--aggressive` updates) |
| **High impact / manual** | DroidReaver cannot apply automatically (upgrade Python, install JDK, plug in a device) |

Every `droidreaver fix` run prints a legend panel explaining these before the plan. Use `--no-legend` to hide it.

## Roadmap: Pentest Environment

DroidReaver aims to become a batteries-included Android pentest environment:

- **Today** — tool registry, version pinning, doctor, fix, frida-server push
- **Next** — environment profiles (`minimal`, `dynamic`, `full`), PATH/setup shell hook, workspace templates
- **Future** — bundled configs (mitmproxy certs, MobSF docker compose), project scaffolds, CI-ready headless mode

## GitHub API

Release versions are fetched from the GitHub Releases API with a 1-hour cache in `~/.droidreaver/cache/`. Set `GITHUB_TOKEN` to avoid rate limits.

On Kali or shared networks you may hit unauthenticated GitHub API limits during
`droidreaver up`, `install`, or `fix --bootstrap`. Create a fine-grained GitHub
token with read-only public repository access and export it before retrying:

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
droidreaver fix --bootstrap
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
