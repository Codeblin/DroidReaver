# Security Policy

DroidReaver is an Android security tool manager. It downloads and launches third-party tools, so security issues in DroidReaver itself can affect real assessment workstations and devices.

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

Pre-1.0 releases may change quickly, but security fixes for the latest minor release are prioritized.

## Reporting a Vulnerability

Please do not open a public issue for a suspected vulnerability.

Preferred reporting channel:

- GitHub Security Advisories: <https://github.com/Codeblin/droidreaver/security/advisories/new>

If GitHub advisories are not available to you, open a minimal public issue asking for a private contact path without including exploit details.

Please include:

- Affected DroidReaver version or commit
- Host OS and Python version
- The command you ran
- Impact and reproduction steps
- Any downloaded artifact URL, checksum, or lockfile involved

## Scope

In scope:

- Unsafe download, extraction, or execution behavior
- PATH or command-dispatch hijacking
- Lockfile, registry, or pinning behavior that installs an unexpected tool/version
- Credential leakage, including `GITHUB_TOKEN`
- Device commands that expose local engagement data unexpectedly

Out of scope:

- Vulnerabilities in third-party tools DroidReaver installs, unless DroidReaver makes them worse
- Expected effects of running tools like Frida, Objection, adb, or mitmproxy against a device you control
- Issues requiring malicious local administrator/root access

## Disclosure Expectations

You should receive an initial response within 7 days. Confirmed vulnerabilities will get a coordinated fix and advisory where appropriate.
