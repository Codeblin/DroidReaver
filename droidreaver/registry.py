"""Tool registry and dependency graph for DroidReaver."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Tool:
    name: str
    display_name: str
    category: str
    install_method: str  # pip, github_release, apt, brew, npm, manual
    pip_package: str | None = None
    github_repo: str | None = None
    binary_name: str | None = None
    version_cmd: str | None = None
    depends_on: tuple[str, ...] = ()
    pin_with: tuple[str, ...] = ()
    frida_server: bool = False
    notes: str | None = None
    description: str | None = None
    npm_package: str | None = None
    apt_package: str | None = None
    brew_package: str | None = None
    manual_url: str | None = None
    github_asset_pattern: str | None = None
    cli_aliases: tuple[str, ...] = ()  # extra invocations (e.g. frida-ps → frida-tools)
    run_module: str | None = None  # python -m module when no binary on PATH
    # Direct download archive URL for install_method="direct". {platform} expands
    # to windows/linux/darwin (see installer._platform_download_key).
    download_url_template: str | None = None
    # Optional SHA-256 digest for direct downloads. A mapping may be used when
    # each platform archive has a different digest.
    download_sha256: str | dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "category": self.category,
            "install_method": self.install_method,
            "pip_package": self.pip_package,
            "github_repo": self.github_repo,
            "binary_name": self.binary_name,
            "version_cmd": self.version_cmd,
            "depends_on": list(self.depends_on),
            "pin_with": list(self.pin_with),
            "frida_server": self.frida_server,
            "notes": self.notes,
            "download_sha256": self.download_sha256,
        }


FRIDA_PIN_GROUP: tuple[str, ...] = (
    "frida",
    "frida-tools",
    "objection",
    "r2frida",
    "medusa",
)

_CATEGORIES = (
    "dynamic_analysis",
    "static_analysis",
    "traffic_interception",
    "device_adb",
    "apk_manipulation",
    "automated_scanners",
    "data_storage",
    "network",
)


def _frida_pins() -> tuple[str, ...]:
    return FRIDA_PIN_GROUP


TOOLS: dict[str, Tool] = {}


def _register(tool: Tool) -> None:
    TOOLS[tool.name] = tool


# --- Dynamic Analysis ---
_register(
    Tool(
        name="frida",
        display_name="Frida",
        category="dynamic_analysis",
        install_method="pip",
        pip_package="frida",
        binary_name="frida",
        version_cmd="frida --version",
        pin_with=_frida_pins(),
        frida_server=True,
        description="Dynamic instrumentation toolkit",
        notes="Core dependency for objection, r2frida, medusa. Version must match frida-server on device.",
    )
)
_register(
    Tool(
        name="frida-tools",
        display_name="Frida Tools",
        category="dynamic_analysis",
        install_method="pip",
        pip_package="frida-tools",
        binary_name="frida-ps",
        version_cmd="frida-ps --version",
        cli_aliases=("frida-ps", "frida-ls", "frida-trace", "frida-discover", "frida-kill"),
        depends_on=("frida",),
        pin_with=_frida_pins(),
        description="CLI utilities for Frida",
    )
)
_register(
    Tool(
        name="objection",
        display_name="Objection",
        category="dynamic_analysis",
        install_method="pip",
        pip_package="objection",
        binary_name="objection",
        version_cmd="objection --version",
        depends_on=("frida",),
        pin_with=_frida_pins(),
        description="Runtime mobile exploration toolkit powered by Frida",
    )
)
_register(
    Tool(
        name="r2frida",
        display_name="r2frida",
        category="dynamic_analysis",
        install_method="pip",
        pip_package="r2frida",
        binary_name="r2frida",
        version_cmd="r2frida --version",
        depends_on=("frida", "radare2"),
        pin_with=_frida_pins(),
        description="Frida bridge for Radare2",
        notes="Also installable via r2pm; pip is preferred for version pinning.",
    )
)
_register(
    Tool(
        name="medusa",
        display_name="Medusa",
        category="dynamic_analysis",
        install_method="git",
        github_repo="Ch0pin/medusa",
        binary_name="medusa",
        version_cmd="medusa --version",
        depends_on=("frida",),
        pin_with=_frida_pins(),
        description="Dynamic analysis and hooking framework",
        notes=(
            "Cloned from GitHub + pip requirements. Git optional (zip fallback). "
            "Upstream: Linux/macOS recommended; limited on Windows."
        ),
    )
)

# --- Static Analysis ---
_register(
    Tool(
        name="jadx",
        display_name="JADX",
        category="static_analysis",
        install_method="github_release",
        github_repo="skylot/jadx",
        binary_name="jadx",
        version_cmd="jadx --version",
        description="Dex to Java decompiler",
        github_asset_pattern="jadx-{version}.zip",
        notes="Requires Java 11+. Extract and add bin/ to PATH or use install_dir.",
    )
)
_register(
    Tool(
        name="apktool",
        display_name="Apktool",
        category="static_analysis",
        install_method="github_release",
        github_repo="iBotPeaches/Apktool",
        binary_name="apktool",
        version_cmd="apktool --version",
        description="Reverse engineering tool for Android APK files",
        github_asset_pattern="apktool_{version}.jar",
        notes="Requires Java. Wrapper script + jar installed to install_dir.",
    )
)
_register(
    Tool(
        name="smali",
        display_name="smali",
        category="static_analysis",
        install_method="github_release",
        github_repo="JesusFreke/smali",
        binary_name="smali",
        version_cmd="smali --version",
        description="Assembler/disassembler for dex format",
        github_asset_pattern="smali-{version}.jar",
    )
)
_register(
    Tool(
        name="baksmali",
        display_name="baksmali",
        category="static_analysis",
        install_method="github_release",
        github_repo="JesusFreke/smali",
        binary_name="baksmali",
        version_cmd="baksmali --version",
        description="Disassembler for dex format",
        github_asset_pattern="baksmali-{version}.jar",
    )
)
_register(
    Tool(
        name="dex2jar",
        display_name="dex2jar",
        category="static_analysis",
        install_method="github_release",
        github_repo="pxb1988/dex2jar",
        binary_name="d2j-dex2jar",
        version_cmd="d2j-dex2jar --version",
        description="Convert dex files to jar",
        github_asset_pattern="dex-tools-{version}.zip",
    )
)
_register(
    Tool(
        name="enjarify",
        display_name="Enjarify",
        category="static_analysis",
        install_method="pip",
        pip_package="enjarify",
        binary_name="enjarify",
        description="Alternative dex to jar converter",
    )
)
_register(
    Tool(
        name="ghidra",
        display_name="Ghidra",
        category="static_analysis",
        install_method="manual",
        manual_url="https://github.com/NationalSecurityAgency/ghidra/releases",
        description="NSA software reverse engineering suite",
        notes="Download from NSA GitHub releases. Manual install only.",
    )
)
_register(
    Tool(
        name="radare2",
        display_name="Radare2",
        category="static_analysis",
        install_method="apt",
        apt_package="radare2",
        brew_package="radare2",
        binary_name="r2",
        version_cmd="r2 -v",
        description="Reverse engineering framework",
        notes="Install via apt/brew or build from source on unsupported platforms.",
    )
)

# --- Traffic Interception ---
_register(
    Tool(
        name="mitmproxy",
        display_name="mitmproxy",
        category="traffic_interception",
        install_method="pip",
        pip_package="mitmproxy",
        binary_name="mitmproxy",
        version_cmd="mitmproxy --version",
        cli_aliases=("mitmdump", "mitmweb"),
        description="Interactive HTTPS proxy",
    )
)
_register(
    Tool(
        name="apk-mitm",
        display_name="apk-mitm",
        category="traffic_interception",
        install_method="npm",
        npm_package="apk-mitm",
        binary_name="apk-mitm",
        version_cmd="apk-mitm --version",
        depends_on=("apktool",),
        description="Patch APKs for HTTPS interception",
        notes="Requires Node.js and npm.",
    )
)
_register(
    Tool(
        name="httptoolkit",
        display_name="HTTP Toolkit",
        category="traffic_interception",
        install_method="manual",
        manual_url="https://httptoolkit.com/",
        description="HTTP(S) debugging proxy",
        notes="Download desktop app from httptoolkit.com. Manual install only.",
    )
)
_register(
    Tool(
        name="burp-suite",
        display_name="Burp Suite",
        category="traffic_interception",
        install_method="manual",
        manual_url="https://portswigger.net/burp/releases",
        description="Web vulnerability scanner and proxy",
        notes="Commercial tool. Download from PortSwigger. Manual install only.",
    )
)

# --- Device & ADB ---
_register(
    Tool(
        name="adb",
        display_name="Android Debug Bridge",
        category="device_adb",
        install_method="direct",
        download_url_template=(
            "https://dl.google.com/android/repository/platform-tools-latest-{platform}.zip"
        ),
        binary_name="adb",
        version_cmd="adb version",
        cli_aliases=("fastboot",),
        description="Android platform tools (adb, fastboot)",
        notes="Official Google platform-tools bundle. Also available via apt (android-tools-adb).",
        apt_package="android-tools-adb",
    )
)
_register(
    Tool(
        name="scrcpy",
        display_name="scrcpy",
        category="device_adb",
        install_method="github_release",
        github_repo="Genymobile/scrcpy",
        binary_name="scrcpy",
        version_cmd="scrcpy --version",
        apt_package="scrcpy",
        brew_package="scrcpy",
        description="Display and control Android devices",
    )
)
_register(
    Tool(
        name="pidcat",
        display_name="pidcat",
        category="device_adb",
        install_method="pip",
        pip_package="pidcat",
        binary_name="pidcat",
        description="Colored logcat for a specific app",
        notes="Requires adb in PATH.",
    )
)
_register(
    Tool(
        name="androguard",
        display_name="Androguard",
        category="device_adb",
        install_method="pip",
        pip_package="androguard",
        binary_name="androguard",
        version_cmd="androguard --version",
        description="Python tool to play with Android files",
    )
)

# --- APK Manipulation ---
_register(
    Tool(
        name="uber-apk-signer",
        display_name="uber-apk-signer",
        category="apk_manipulation",
        install_method="github_release",
        github_repo="patrickfav/uber-apk-signer",
        binary_name="uber-apk-signer",
        github_asset_pattern="uber-apk-signer-{version}.jar",
        description="Sign and zip-align APKs",
        notes="Java jar; run with java -jar.",
    )
)
_register(
    Tool(
        name="apksigner",
        display_name="apksigner",
        category="apk_manipulation",
        install_method="manual",
        binary_name="apksigner",
        description="APK signing tool",
        notes="Bundled with Android SDK build-tools. Install Android SDK or set path manually.",
    )
)
_register(
    Tool(
        name="zipalign",
        display_name="zipalign",
        category="apk_manipulation",
        install_method="manual",
        binary_name="zipalign",
        description="APK alignment tool",
        notes="Bundled with Android SDK build-tools.",
    )
)

# --- Automated Scanners ---
_register(
    Tool(
        name="mobsf",
        display_name="MobSF",
        category="automated_scanners",
        install_method="pip",
        pip_package="mobsf",
        binary_name="mobsf",
        github_repo="MobSF/Mobile-Security-Framework-MobSF",
        description="Mobile Security Framework",
        notes="Also available as Docker image from MobSF/Mobile-Security-Framework-MobSF.",
    )
)
_register(
    Tool(
        name="drozer",
        display_name="Drozer",
        category="automated_scanners",
        install_method="pip",
        pip_package="drozer",
        binary_name="drozer",
        description="Android security assessment framework",
        notes="Legacy tool; may require additional setup for agent APK.",
    )
)
_register(
    Tool(
        name="nuclei",
        display_name="Nuclei",
        category="automated_scanners",
        install_method="github_release",
        github_repo="projectdiscovery/nuclei",
        binary_name="nuclei",
        version_cmd="nuclei -version",
        description="Fast vulnerability scanner",
    )
)

# --- Data & Storage ---
_register(
    Tool(
        name="sqlitebrowser",
        display_name="DB Browser for SQLite",
        category="data_storage",
        install_method="apt",
        apt_package="sqlitebrowser",
        brew_package="db-browser-for-sqlite",
        binary_name="sqlitebrowser",
        description="Visual SQLite database browser",
    )
)
_register(
    Tool(
        name="binwalk",
        display_name="binwalk",
        category="data_storage",
        install_method="pip",
        pip_package="binwalk",
        binary_name="binwalk",
        version_cmd="binwalk --version",
        apt_package="binwalk",
        description="Firmware analysis tool",
    )
)
_register(
    Tool(
        name="trufflehog",
        display_name="TruffleHog",
        category="data_storage",
        install_method="github_release",
        github_repo="trufflesecurity/trufflehog",
        binary_name="trufflehog",
        version_cmd="trufflehog --version",
        description="Secret scanning tool",
    )
)
_register(
    Tool(
        name="gitleaks",
        display_name="Gitleaks",
        category="data_storage",
        install_method="github_release",
        github_repo="gitleaks/gitleaks",
        binary_name="gitleaks",
        version_cmd="gitleaks version",
        description="Detect secrets in git repos",
    )
)

# --- Network ---
_register(
    Tool(
        name="nmap",
        display_name="Nmap",
        category="network",
        install_method="apt",
        apt_package="nmap",
        brew_package="nmap",
        binary_name="nmap",
        version_cmd="nmap --version",
        description="Network discovery and security scanner",
    )
)
_register(
    Tool(
        name="wireshark",
        display_name="Wireshark",
        category="network",
        install_method="manual",
        manual_url="https://www.wireshark.org/download.html",
        description="Network protocol analyzer (GUI)",
        notes="Install via apt/brew or download from wireshark.org. GUI application.",
        apt_package="wireshark",
        brew_package="wireshark",
    )
)
_register(
    Tool(
        name="tcpdump",
        display_name="tcpdump",
        category="network",
        install_method="apt",
        apt_package="tcpdump",
        brew_package="tcpdump",
        binary_name="tcpdump",
        version_cmd="tcpdump --version",
        description="Packet capture utility",
    )
)


def get_tool(name: str) -> Tool:
    if name not in TOOLS:
        raise KeyError(f"Unknown tool: {name}")
    return TOOLS[name]


def list_tools(category: str | None = None) -> list[Tool]:
    tools = list(TOOLS.values())
    if category:
        tools = [t for t in tools if t.category == category]
    return sorted(tools, key=lambda t: (t.category, t.name))


def get_pin_group(tool_name: str) -> set[str]:
    """Return all tools that share a pin group with tool_name."""
    tool = get_tool(tool_name)
    if not tool.pin_with:
        return {tool_name}
    group: set[str] = set()
    for name, t in TOOLS.items():
        if t.pin_with and set(t.pin_with) & set(tool.pin_with):
            group.add(name)
    group.add(tool_name)
    return group


def get_pin_group_leader(group: set[str]) -> str:
    """Primary pin key stored in config — frida for the frida group."""
    if "frida" in group:
        return "frida"
    return min(group)


class CycleError(Exception):
    """Raised when the dependency graph contains a cycle."""


def topological_sort(tool_names: list[str] | None = None) -> list[str]:
    """Return tool names in dependency order (dependencies first)."""
    names = tool_names if tool_names is not None else list(TOOLS.keys())
    name_set = set(names)
    in_degree: dict[str, int] = {n: 0 for n in names}
    adj: dict[str, list[str]] = {n: [] for n in names}

    for name in names:
        tool = get_tool(name)
        for dep in tool.depends_on:
            if dep in name_set:
                adj[dep].append(name)
                in_degree[name] += 1

    queue = [n for n in names if in_degree[n] == 0]
    queue.sort()
    result: list[str] = []

    while queue:
        node = queue.pop(0)
        result.append(node)
        for neighbor in adj[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
                queue.sort()

    if len(result) != len(names):
        raise CycleError(
            "Dependency cycle detected in tool graph. "
            f"Unresolved: {set(names) - set(result)}"
        )
    return result


def resolve_install_order(tool_names: list[str]) -> list[str]:
    """Expand dependencies and return full install order."""
    to_install: set[str] = set()
    stack = list(tool_names)
    while stack:
        name = stack.pop()
        if name in to_install:
            continue
        to_install.add(name)
        tool = get_tool(name)
        for dep in tool.depends_on:
            if dep not in to_install:
                stack.append(dep)
    return topological_sort(list(to_install))
