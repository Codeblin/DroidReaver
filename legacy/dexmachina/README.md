# DexMachina has been renamed to DroidReaver

> **Deprecated package:** `dexmachina` is now **DroidReaver**.
>
> Install the maintained package instead:
>
> ```bash
> pip install droidreaver
> # or, recommended for CLI use:
> pipx install droidreaver
> ```

This final `dexmachina` release exists only as a transition bridge. It depends
on `droidreaver` and keeps the old `dexmachina` console command as a thin wrapper
so existing scripts do not fail immediately.

New projects should use:

```bash
droidreaver --help
droidreaver up --profile dynamic
```

The old `dexmachina` package is inactive and will be archived on PyPI after
this transition release. Do not start new automation against the old package
name.

Migration:

```bash
pip uninstall dexmachina
pip install droidreaver
```

If you use `pipx`:

```bash
pipx uninstall dexmachina
pipx install droidreaver
```

Project home: <https://github.com/Codeblin/droidreaver>
