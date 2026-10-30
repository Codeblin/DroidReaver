"""Repo-local workspace setup — `droidreaver init` and .gitignore management."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from droidreaver.config import DEFAULT_CONFIG_NAME
from droidreaver.profiles import DEFAULT_PROFILE

# Everything DroidReaver downloads lives under this dir; it is gitignored.
WORKSPACE_DIRNAME = ".droidreaver"
TOOLS_SUBDIR = "tools"
CACHE_SUBDIR = "cache"

GITIGNORE_BLOCK_HEADER = "# DroidReaver - downloaded tools & caches (managed)"
GITIGNORE_ENTRIES: tuple[str, ...] = (
    f"{WORKSPACE_DIRNAME}/{TOOLS_SUBDIR}/",
    f"{WORKSPACE_DIRNAME}/{CACHE_SUBDIR}/",
    f"{WORKSPACE_DIRNAME}/venvs/",
)


@dataclass
class InitResult:
    config_path: Path
    tools_dir: Path
    created_config: bool
    gitignore_path: Path | None = None
    gitignore_added: list[str] = field(default_factory=list)
    profile: str = DEFAULT_PROFILE


def find_git_root(start: Path | None = None) -> Path | None:
    """Walk up from `start` looking for a .git directory."""
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _project_config_body(profile: str) -> str:
    return (
        "# DroidReaver project environment\n"
        "# Tools are downloaded into .droidreaver/tools and added to PATH via\n"
        "#   droidreaver env   (print)   or   droidreaver shell   (subshell)\n"
        "\n"
        "[settings]\n"
        'adb_path = "adb"\n'
        'java_path = "java"\n'
        f'install_dir = "{WORKSPACE_DIRNAME}/{TOOLS_SUBDIR}"\n'
        f'profile = "{profile}"\n'
        "auto_push_frida_server = false\n"
        "\n"
        "[pins]\n"
        "# frida = \"17.11.0\"   # pin the whole frida group\n"
        "\n"
        "[active]\n"
        "\n"
        "[ignored]\n"
        'tools = ["ghidra", "wireshark", "burp-suite", "httptoolkit"]\n'
    )


def update_gitignore(repo_dir: Path) -> tuple[Path, list[str]]:
    """Ensure DroidReaver entries exist in repo .gitignore. Returns (path, added)."""
    gitignore = repo_dir / ".gitignore"
    existing_lines: list[str] = []
    if gitignore.exists():
        existing_lines = gitignore.read_text(encoding="utf-8").splitlines()
    existing = {line.strip() for line in existing_lines}

    to_add = [entry for entry in GITIGNORE_ENTRIES if entry not in existing]
    if not to_add:
        return gitignore, []

    block: list[str] = []
    if existing_lines and existing_lines[-1].strip() != "":
        block.append("")
    block.append(GITIGNORE_BLOCK_HEADER)
    block.extend(to_add)

    with gitignore.open("a", encoding="utf-8") as f:
        f.write("\n".join(block) + "\n")
    return gitignore, to_add


def init_workspace(
    target_dir: Path | None = None,
    *,
    profile: str = DEFAULT_PROFILE,
    force: bool = False,
) -> InitResult:
    """Create a repo-local DroidReaver workspace (config, dirs, gitignore)."""
    repo_dir = (target_dir or find_git_root() or Path.cwd()).resolve()
    config_path = repo_dir / DEFAULT_CONFIG_NAME

    workspace_dir = repo_dir / WORKSPACE_DIRNAME
    tools_dir = workspace_dir / TOOLS_SUBDIR
    tools_dir.mkdir(parents=True, exist_ok=True)
    (workspace_dir / CACHE_SUBDIR).mkdir(parents=True, exist_ok=True)

    created_config = False
    if force or not config_path.exists():
        config_path.write_text(_project_config_body(profile), encoding="utf-8")
        created_config = True

    gitignore_path, added = update_gitignore(repo_dir)

    return InitResult(
        config_path=config_path,
        tools_dir=tools_dir,
        created_config=created_config,
        gitignore_path=gitignore_path,
        gitignore_added=added,
        profile=profile,
    )
