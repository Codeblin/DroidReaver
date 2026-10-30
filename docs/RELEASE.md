# Release Process

DroidReaver releases are tag-driven.

## One-Time PyPI Setup

Create the PyPI project and configure Trusted Publishing before pushing the first release tag.

PyPI Trusted Publisher fields:

- PyPI project: `droidreaver`
- Owner: `Codeblin`
- Repository: `DroidReaver`
- Workflow: `release.yml`
- Environment: `pypi`

GitHub environment:

- Create environment `pypi` in repository settings.
- Require reviewer approval for the environment.
- Restrict deployment branches/tags to release tags if available.

This matches PyPI's Trusted Publishing model: GitHub Actions gets a short-lived OIDC token, PyPI validates that token against the configured publisher, and PyPI mints a short-lived upload token. No long-lived PyPI token is stored in GitHub.

## Cut A Release

1. Make sure `pyproject.toml`, `droidreaver/__init__.py`, and `CHANGELOG.md` all reference the same version.
2. Run:

```bash
python scripts/verify_release.py v0.1.0
python -m pytest
```

3. Commit the release changes.
4. Tag and push:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The release workflow will:

- validate release metadata,
- run tests,
- build distributions,
- create a GitHub Release,
- publish to PyPI through Trusted Publishing.

## If Publishing Fails

- Confirm the PyPI Trusted Publisher fields match this repository and workflow exactly.
- Confirm the GitHub environment is named `pypi`.
- Confirm the workflow has `id-token: write`.
- Re-run the tag workflow after fixing configuration.

## Final DexMachina Transition Release

Before archiving the old `dexmachina` PyPI project, publish one final
transition release from `legacy/dexmachina`.

This package is intentionally separate from the maintained `droidreaver` package.
It:

- uses PyPI name `dexmachina`,
- has `Development Status :: 7 - Inactive`,
- depends on `droidreaver`,
- exposes a deprecated `dexmachina` CLI wrapper,
- prints a rename notice before delegating to DroidReaver.

Build locally:

```bash
python -m pip install --upgrade build twine
cd legacy/dexmachina
python -m build
python -m twine check dist/*
```

Publish after `droidreaver` exists on PyPI:

```bash
python -m twine upload dist/*
```

After the transition release is visible on PyPI, archive the old project at:

```text
https://pypi.org/manage/project/dexmachina/settings/
```

Do not delete the project or old releases. Archiving keeps the old name reserved
and visibly redirects users without creating a package-squatting gap.
