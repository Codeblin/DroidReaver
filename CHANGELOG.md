# Changelog

All notable changes to DroidReaver are documented here. This project follows Semantic Versioning while it is pre-1.0, with minor releases allowed to refine CLI behavior.

## [Unreleased]

### Changed

- Rename the project and maintained package to **DroidReaver** (`droidreaver` CLI/package).
- Workspace paths, lockfile, config, env vars, and install metadata now use the `droidreaver` name.
- Point the legacy `dexmachina` transition package at `droidreaver`.

## [0.2.0] - 2026-07-17

### Changed

- Rename the project and maintained package from DexMachina to DroidReaver.
- Add a legacy `dexmachina` transition package for one final inactive PyPI release.
- Add a migration guide for old installs, scripts, config files, and workspace paths.


## [0.1.1] - 2026-07-15

### Fixed

- Resolve DroidReaver-managed adb during doctor, fix, and device flows.
- Run Frida doctor checks through DroidReaver's managed environment.
- Reload config before fix re-checks so active Frida venv changes are visible.
- Avoid false incomplete-download failures for Google platform-tools decoded responses.
- Improve GitHub API rate-limit guidance during installs.

### Documentation

- Document Kali-safe pipx installation.
- Document managed PATH usage with `droidreaver shell` and `droidreaver env`.
- Document `GITHUB_TOKEN` retry path for GitHub API rate limits.

## [0.1.0] - 2026-07-14

### Added

- Initial public alpha version marker.
- CI matrix across Ubuntu, macOS, and Windows.
- Android/ADB smoke test.
- Shell-only rooted emulator integration workflow compatible with owner-only Actions policies.
- Trust and supply-chain model documentation.
- Security policy and coordinated disclosure process.
- Contribution guide with registry extension instructions.
- Dependabot configuration for Python dependencies.
- Atomic direct downloads with incomplete-body rejection.
- Optional SHA-256 verification support for direct-download registry entries.
- GitHub Release checksum discovery for common upstream checksum assets.
- Lockfile artifact digest recording and restore-time digest enforcement.
- Safe archive extraction that rejects path traversal members.
- Release metadata validation and GitHub release workflow for `v*` tags.
- PyPI Trusted Publishing workflow using GitHub OIDC and `uv publish`.
- CODEOWNERS and branch protection checklist.
- Release process documentation.

### Known Gaps

- GitHub Release assets are checksum-verified only when upstream publishes a discoverable checksum file or a lockfile digest is available.
- Signature verification is not implemented yet.
- PyPI project Trusted Publisher configuration still must be completed in PyPI/GitHub settings before the first upload.
