"""Environment profiles — curated tool bundles for one-command setup."""

from __future__ import annotations

from droidreaver.registry import TOOLS

# Ordered profiles from smallest to largest. Each maps to registry tool names.
# 'full' is computed from the registry (all auto-installable tools).
PROFILES: dict[str, tuple[str, ...]] = {
    "minimal": ("adb", "frida", "frida-tools"),
    "dynamic": (
        "adb",
        "frida",
        "frida-tools",
        "objection",
        "r2frida",
        "medusa",
    ),
    "static": ("jadx", "apktool", "smali", "baksmali", "dex2jar", "enjarify"),
    "traffic": ("mitmproxy", "apk-mitm"),
    "scanners": ("mobsf", "nuclei", "drozer"),
}

PROFILE_DESCRIPTIONS: dict[str, str] = {
    "minimal": "adb + frida runtime + frida-tools — the smallest working kit",
    "dynamic": "Dynamic analysis: frida stack, objection, r2frida, medusa",
    "static": "Static analysis: jadx, apktool, smali/baksmali, dex2jar",
    "traffic": "Traffic interception: mitmproxy + apk-mitm",
    "scanners": "Automated scanners: MobSF, nuclei, drozer",
    "full": "Everything auto-installable in the registry",
}

DEFAULT_PROFILE = "dynamic"


def _full_profile() -> tuple[str, ...]:
    return tuple(
        name for name, tool in TOOLS.items() if tool.install_method != "manual"
    )


def profile_names() -> list[str]:
    return [*PROFILES.keys(), "full"]


def resolve_profile(name: str) -> list[str]:
    """Return the registry tool names for a profile (deduped, order-preserving)."""
    key = name.strip().lower()
    if key == "full":
        members: tuple[str, ...] = _full_profile()
    elif key in PROFILES:
        members = PROFILES[key]
    else:
        raise KeyError(name)

    seen: set[str] = set()
    ordered: list[str] = []
    for tool_name in members:
        if tool_name in TOOLS and tool_name not in seen:
            seen.add(tool_name)
            ordered.append(tool_name)
    return ordered


def profile_description(name: str) -> str:
    return PROFILE_DESCRIPTIONS.get(name.lower(), "")
