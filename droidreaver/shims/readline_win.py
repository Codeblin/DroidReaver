"""Windows readline compatibility for tools that hard-import readline (e.g. Medusa)."""

from __future__ import annotations

import sys
import types


def _noop(*_args, **_kwargs) -> None:
    pass


def _readline_stub() -> types.ModuleType:
    stub = types.ModuleType("readline")
    stub.__doc__ = "droidreaver readline stub (Windows)"
    stub.parse_and_bind = _noop
    stub.set_completer = _noop
    stub.set_completer_delims = _noop
    stub.get_line_buffer = lambda: ""
    stub.insert_text = _noop
    stub.read_init_file = _noop
    stub.add_history = _noop
    stub.set_history_length = _noop
    stub.clear_history = _noop
    stub.get_completer = lambda: None
    stub.get_completion_type = lambda: 0
    stub.get_begidx = lambda: 0
    stub.get_endidx = lambda: 0
    stub.redisplay = _noop
    return stub


def install_readline_shim() -> None:
    """Register a readline module before importing Linux-oriented REPL tools."""
    if sys.platform != "win32":
        return
    if "readline" in sys.modules:
        return
    try:
        import readline as _real  # noqa: F401
    except ImportError:
        sys.modules["readline"] = _readline_stub()
