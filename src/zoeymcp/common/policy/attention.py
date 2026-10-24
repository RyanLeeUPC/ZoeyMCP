"""The attention decision: what in one server's listing needs the operator (M6 design J.5;
G-20, Y29). Pure.

:func:`attention` reads a server's listing as names and pins, the view's ``include``, ``review``
and ``declined`` maps for it, and its drift marks, and sorts what needs the operator into five
lists:

- ``drifted``: an included tool listed at a pin other than the policy's, or with no pin at all
  (the listing reports it invalid or duplicate, so it is hidden, or blocks an ``on_drift: fail``
  server);
- ``marked``: an included tool listed at its pin and still hidden by a drift mark (``review
  --clear`` once it matches);
- ``new``: a listed tool that is neither included nor declined, so nobody reviewed it;
- ``changed_declined``: a declined tool listed at another pin than the one declined, which counts
  again (Y20);
- ``missing``: an included tool the server doesn't list.

A tool listed with no pin (one the listing reports invalid or duplicate) that isn't included
can't be declined, so it is none of these: the listing reports it on its own. :func:`quiet` says
whether nothing needs the operator. The gateway's review report and status, ``zoeymcp
review``'s exit code, and the vault's health and Home all call this one decision, so they can't
disagree.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Set
from dataclasses import dataclass, fields
from typing import Any, Protocol

from .schema import Tools


class Server(Protocol):
    """What :func:`attention` reads of a server: a view's remote or toolkit server, or a
    ``pinning: off`` toolkit's own pins."""

    @property
    def tools(self) -> Tools: ...

    @property
    def review(self) -> Mapping[str, str]: ...

    @property
    def declined(self) -> Mapping[str, str]: ...


@dataclass(frozen=True)
class Attention:
    """What needs the operator in one server's listing, each list sorted."""

    drifted: tuple[str, ...] = ()
    marked: tuple[str, ...] = ()
    new: tuple[str, ...] = ()
    changed_declined: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def unreviewed(self) -> tuple[str, ...]:
        """The tools nobody reviewed at the pin listed now: the new ones and the declined ones
        that changed, sorted."""
        return tuple(sorted({*self.new, *self.changed_declined}))

    def as_dict(self) -> dict[str, list[str]]:
        """The plain form a review report and the gateway's status carry."""
        return {member.name: list(getattr(self, member.name)) for member in fields(self)}


def attention(
    listed: Mapping[str, str | None], server: Server, marks: Set[tuple[str, str]]
) -> Attention:
    """The decision for one listing: ``listed`` maps each name listed to its pin, or ``None``
    for a tool that can't be pinned; ``marks`` are the server's drift marks as (tool, the pin
    it drifted from), of which only those at the policy's pin still hold."""
    included = set(server.tools.include)
    review, declined = server.review, server.declined
    held = {tool for tool, pinned in marks if review.get(tool) == pinned}
    drifted: list[str] = []
    marked: list[str] = []
    new: list[str] = []
    changed: list[str] = []
    for name, pin in listed.items():
        if name in included:
            pinned = review.get(name)
            if pinned is not None and pin != pinned:  # a None pin: invalid or duplicate now
                drifted.append(name)
            elif name in held:
                marked.append(name)
        elif pin is None:
            continue
        elif name not in declined:
            new.append(name)
        elif declined[name] != pin:
            changed.append(name)
    return Attention(
        drifted=tuple(sorted(drifted)),
        marked=tuple(sorted(marked)),
        new=tuple(sorted(new)),
        changed_declined=tuple(sorted(changed)),
        missing=tuple(sorted(included - set(listed))),
    )


def quiet(found: Attention) -> bool:
    """Whether nothing in ``found`` needs the operator."""
    return not any(getattr(found, member.name) for member in fields(found))


def combined(found: Iterable[Attention]) -> Attention:
    """Several listings' decisions as one (a server's connections each list it): every name in
    any of them, sorted."""
    each = list(found)
    return Attention(
        *(
            tuple(sorted({name for one in each for name in getattr(one, member.name)}))
            for member in fields(Attention)
        )
    )


def loaded(data: Mapping[str, Any]) -> Attention:
    """An :class:`Attention` from its plain form (:meth:`Attention.as_dict`); a list it doesn't
    hold is empty."""
    return Attention(*(tuple(sorted(data.get(member.name, ()))) for member in fields(Attention)))
