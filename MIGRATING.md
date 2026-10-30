# Migrating from DexMachina to DroidReaver

DexMachina has been renamed to **DroidReaver**.

The maintained package and CLI are now:

```bash
pipx install droidreaver
droidreaver --help
```

The old `dexmachina` PyPI package receives one final transition release that
depends on `droidreaver` and keeps the old `dexmachina` command as a compatibility
wrapper. It prints a deprecation notice on every invocation.

## What changed

| Old | New |
| --- | --- |
| `dexmachina` PyPI package | `droidreaver` PyPI package |
| `dexmachina` CLI | `droidreaver` CLI |
| `python -m dexmachina` | `python -m droidreaver` |
| `dexmachina.toml` | `droidreaver.toml` |
| `dexmachina.lock.toml` | `droidreaver.lock.toml` |
| `.dexmachina/` workspace | `.droidreaver/` workspace |
| `DEXMACHINA_NO_BANNER` | `DROIDREAVER_NO_BANNER` |

## Recommended upgrade

```bash
pipx uninstall dexmachina
pipx install droidreaver
droidreaver --help
```

For virtual environments:

```bash
python -m pip uninstall dexmachina
python -m pip install droidreaver
droidreaver --help
```

## Workspace migration

If you have an old workspace, rename the files and directory:

```bash
mv dexmachina.toml droidreaver.toml
mv dexmachina.lock.toml droidreaver.lock.toml
mv .dexmachina .droidreaver
```

Then update `install_dir` inside `droidreaver.toml` if it still points at the old path.

## PyPI status

After the final `dexmachina` transition release is published, the old PyPI
project should be archived, not deleted. Archiving keeps the name reserved and
visible while signalling that future work has moved to DroidReaver.
