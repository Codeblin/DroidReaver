"""Tests for tool runtime dispatch."""

from droidreaver.runtime import (
    RESERVED_COMMANDS,
    lookup_invocation,
    list_runnable_tools,
)


def test_frida_invocation():
    inv = lookup_invocation("frida")
    assert inv is not None
    assert inv.tool.name == "frida"
    assert inv.executable == "frida"


def test_frida_ps_alias():
    inv = lookup_invocation("frida-ps")
    assert inv is not None
    assert inv.tool.name == "frida-tools"
    assert inv.executable == "frida-ps"


def test_runnable_does_not_include_reserved():
    names = {i.name for i in list_runnable_tools()}
    assert names.isdisjoint(RESERVED_COMMANDS)


def test_frida_kill_requires_args():
    inv = lookup_invocation("frida-kill")
    assert inv is not None
    assert inv.requires_args is True


def test_prepare_dispatch_empty_frida_kill():
    from droidreaver.runtime import prepare_dispatch_args

    inv = lookup_invocation("frida-kill")
    assert inv is not None
    args = prepare_dispatch_args(inv, [])
    assert args == ["--help"]


def test_prepare_dispatch_passes_through():
    from droidreaver.runtime import prepare_dispatch_args

    inv = lookup_invocation("frida-kill")
    assert inv is not None
    args = prepare_dispatch_args(inv, ["-U", "1234"])
    assert args == ["-U", "1234"]


def test_objection_invocation():
    inv = lookup_invocation("objection")
    assert inv is not None
    assert inv.tool.name == "objection"
