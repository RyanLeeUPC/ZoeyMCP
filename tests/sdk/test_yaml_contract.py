"""Contract 56 (M6 design O.2): what the strict YAML loader relies on in PyYAML's parser and
resolver.

``common.yamlload`` refuses an explicit tag by reading the parser's events (B1), so an event's
``tag`` must be ``None`` for every untagged node and the tag for an explicit one, for scalars,
sequences and mappings alike. It types plain scalars by replacing the implicit resolvers (and
refuses a long run of digits by an event's ``implicit`` flag, B5), so a plain scalar's resolved tag
must come from those resolvers alone, keyed by its first character, and fall back to ``str``.

It joins D-95's re-run list: run again on every PyYAML bump.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from zoeymcp.common.yamlload import StrictLoader

STR = "tag:yaml.org,2002:str"
INT = "tag:yaml.org,2002:int"
NODE_EVENTS = (yaml.ScalarEvent, yaml.SequenceStartEvent, yaml.MappingStartEvent)


def events(text: str) -> list[Any]:
    return [
        event
        for event in yaml.parse(text, Loader=yaml.SafeLoader)
        if isinstance(event, NODE_EVENTS)
    ]


@pytest.mark.parametrize(
    "text",
    [
        "a: x",
        "a: 'x'",
        'a: "x"',
        "a: |\n  x\n",
        "a: >\n  x\n",
        "a: [x, 'y']",
        "a: {b: x}",
        "a:\n  - x\n",
        "a:\n  b: x\n",
        "a:\n",
        "? [x]\n: y\n",
    ],
)
def test_an_untagged_node_has_no_tag(text: str) -> None:
    found = events(text)
    assert found
    assert [event.tag for event in found] == [None] * len(found)


@pytest.mark.parametrize(
    ("text", "kind", "tag"),
    [
        ("a: !!str x", yaml.ScalarEvent, STR),
        ('a: !!str "x"', yaml.ScalarEvent, STR),
        ("a: !!str", yaml.ScalarEvent, STR),
        ("a: !!int |\n  1\n", yaml.ScalarEvent, INT),
        ("a: ! x", yaml.ScalarEvent, "!"),
        ("a: !local x", yaml.ScalarEvent, "!local"),
        ("a: !<tag:example.com,2000:x> x", yaml.ScalarEvent, "tag:example.com,2000:x"),
        ("a: !!seq [x]", yaml.SequenceStartEvent, "tag:yaml.org,2002:seq"),
        ("a: !x\n  - y\n", yaml.SequenceStartEvent, "!x"),
        ("a: !!map {b: x}", yaml.MappingStartEvent, "tag:yaml.org,2002:map"),
        ("a: !x\n  b: y\n", yaml.MappingStartEvent, "!x"),
        (
            "%TAG !e! tag:example.com,2000:\n---\na: !e!x y\n",
            yaml.ScalarEvent,
            "tag:example.com,2000:x",
        ),
    ],
)
def test_an_explicit_tag_is_on_its_event(text: str, kind: type, tag: str) -> None:
    tagged = [event for event in events(text) if event.tag is not None]
    assert [(type(event), event.tag) for event in tagged] == [(kind, tag)]


def test_only_a_plain_scalar_is_implicit_for_the_resolvers() -> None:
    text = "a: '1'\nb: \"1\"\nc: |\n  1\nd: 1\n"
    scalars = [event for event in events(text) if isinstance(event, yaml.ScalarEvent)]
    found = [(event.value, event.implicit) for event in scalars]
    plain, other = (True, False), (False, True)
    assert found == [
        ("a", plain),
        ("1", other),
        ("b", plain),
        ("1", other),
        ("c", plain),
        ("1\n", other),
        ("d", plain),
        ("1", plain),
    ]


class Bare(yaml.SafeLoader):
    """A SafeLoader with no implicit resolvers at all."""


Bare.yaml_implicit_resolvers = {}


def composed(text: str, loader: type[yaml.SafeLoader]) -> dict[str, str]:
    root = yaml.compose(text, Loader=loader)
    assert isinstance(root, MappingNode)
    return {key.value: value.tag for key, value in root.value}


def test_a_plain_scalars_tag_comes_from_the_implicit_resolvers_only() -> None:
    text = "a: 1\nb: true\nc: 1.5\nd: ~\ne: 2026-10-23\nf: x\n"
    assert set(composed(text, Bare).values()) == {STR}
    assert composed(text, StrictLoader) == {
        "a": INT,
        "b": "tag:yaml.org,2002:bool",
        "c": "tag:yaml.org,2002:float",
        "d": "tag:yaml.org,2002:null",
        "e": STR,
        "f": STR,
    }
    # A quoted scalar is a string whatever the resolvers say.
    assert composed("a: '1'\nb: \"true\"\n", StrictLoader) == {"a": STR, "b": STR}


def test_the_resolvers_are_keyed_by_first_character() -> None:
    table = yaml.SafeLoader.yaml_implicit_resolvers
    assert isinstance(table, dict)
    # One character, or '' for the empty scalar.
    assert all(isinstance(first, str) and len(first) <= 1 for first in table)
    for resolvers in table.values():
        assert all(isinstance(tag, str) and hasattr(regex, "match") for tag, regex in resolvers)

    class OnlyDigits(yaml.SafeLoader):
        pass

    [regex] = [regex for tag, regex in StrictLoader.yaml_implicit_resolvers["1"] if tag == INT]
    OnlyDigits.yaml_implicit_resolvers = {}
    OnlyDigits.add_implicit_resolver(INT, regex, ["1"])
    # "2" isn't a first character the resolver was added for, so it stays a string.
    assert composed("a: 1\nb: 2\n", OnlyDigits) == {"a": INT, "b": STR}


def test_a_composed_node_is_hashable_by_identity() -> None:
    # The loader keys each collection's place in the document by its node.
    root = yaml.compose("a: [x]\nb: [x]\n", Loader=yaml.SafeLoader)
    assert isinstance(root, MappingNode)
    first, second = (value for _, value in root.value)
    assert isinstance(first, SequenceNode)
    assert isinstance(second, SequenceNode)
    assert first != second
    assert len({first: 1, second: 2}) == 2
    assert isinstance(first.value[0], ScalarNode)
