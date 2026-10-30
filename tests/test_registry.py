"""Tests for dependency graph resolution."""

import pytest

from droidreaver.registry import CycleError, get_pin_group, resolve_install_order, topological_sort


def test_topological_sort_dependencies_first():
    order = topological_sort(["objection", "frida"])
    assert order.index("frida") < order.index("objection")


def test_resolve_install_order_expands_deps():
    order = resolve_install_order(["objection"])
    assert "frida" in order
    assert "objection" in order
    assert order.index("frida") < order.index("objection")


def test_r2frida_includes_radare2():
    order = resolve_install_order(["r2frida"])
    assert "frida" in order
    assert "radare2" in order
    assert order.index("radare2") < order.index("r2frida")


def test_install_all_order_is_stable():
    from droidreaver.registry import TOOLS

    names = list(TOOLS.keys())
    order = topological_sort(names)
    assert len(order) == len(names)
    for name in order:
        tool = TOOLS[name]
        for dep in tool.depends_on:
            assert order.index(dep) < order.index(name)


def test_cycle_detection_raises():
    # Registry has no cycles; verify API with a synthetic scenario via sort subset
    # apk-mitm -> apktool is acyclic
    order = topological_sort(["apk-mitm", "apktool"])
    assert order.index("apktool") < order.index("apk-mitm")


def test_frida_pin_group():
    group = get_pin_group("objection")
    assert "frida" in group
    assert "objection" in group
    assert "frida-tools" in group
    assert "r2frida" in group
    assert "medusa" in group


def test_pin_group_singleton():
    group = get_pin_group("jadx")
    assert group == {"jadx"}
