# Contributing to DroidReaver

Thanks for helping make DroidReaver more reliable for real Android security work.

## Local Setup

```bash
git clone https://github.com/Codeblin/droidreaver.git
cd droidreaver
python -m pip install -e ".[dev]"
python -m pytest
```

Run coverage locally:

```bash
python -m pytest --cov=droidreaver --cov-report=term-missing
```

## Development Expectations

- Keep changes small and focused.
- Add tests for registry, install, config, lockfile, doctor, fix, or device behavior when you touch those paths.
- Prefer deterministic tests that do not require a device unless the test is explicitly an integration test.
- Do not add new network calls without documenting them in `THREAT_MODEL.md`.
- Do not make `fix` or install commands touch unrelated user files.

## Adding a Tool to the Registry

Most contributions will be a registry entry plus a test.

1. Add a `Tool(...)` entry in `droidreaver/registry.py`.
2. Pick the narrowest install method: `pip`, `github_release`, `direct`, `npm`, `apt`, `brew`, `git`, or `manual`.
3. Add `depends_on` for required tools, for example `apk-mitm` depends on `apktool`.
4. Add `pin_with` only when versions must move together.
5. Add `binary_name`, `version_cmd`, and `cli_aliases` so `status`, `arsenal`, and direct dispatch work.
6. Add `download_sha256` for direct downloads when upstream publishes a stable SHA-256.
7. Add or update tests in `tests/test_registry.py` and installer tests if the install method has special behavior.
8. Document caveats in `notes`; security-sensitive caveats also belong in `THREAT_MODEL.md`.

Example shape:

```python
Tool(
    name="example",
    display_name="Example",
    category="static_analysis",
    install_method="github_release",
    github_repo="owner/example",
    binary_name="example",
    version_cmd="example --version",
    description="Short purpose statement",
)
```

## Pull Requests

All changes should go through pull requests once branch protection is enabled. See `.github/BRANCH_PROTECTION.md` for the repository settings maintainers should enforce.

Before opening a PR:

```bash
python -m pytest
droidreaver --help
droidreaver status --offline
```

If your change affects device flows, include the emulator/device setup you tested against, for example rooted AVD, Genymotion, or Corellium.

## Releases

Release tags and PyPI publishing are documented in `docs/RELEASE.md`.
