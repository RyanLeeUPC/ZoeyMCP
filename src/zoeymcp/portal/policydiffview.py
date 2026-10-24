"""A diff between two policy revisions, as the portal and the admin socket show it (M6 design H.2;
DD-10, Y13). Pure, mutation-tested.

:func:`rows` renders the structured diff (``common/policy/diff.py``'s :class:`~.diff.Change`
list, recomputed from two revisions, never stored) through the policy view's allowlist,
``portal/policyview.py``'s ``FIELDS``, by the schema model and field each change is under:

- a shown field's old and new values as the policy view shows them: every string through
  :func:`.display.shown`, and a whole entry (a client, a credential, a route, a server added,
  removed or replaced) as its model, each of its own hidden fields only as "(set)";
- a hidden field (a client's token or its hash, a placeholder, a username, a connector's sender),
  and one name of a map shown by its names (``token_headers``, forced query values), as
  ``(set)``, ``(changed)`` or ``(removed)`` with no value, old or new;
- a connector's recipients (``to``) as a count.

A row's path is the change's own, field names as the document writes them, every name shown;
its direction is :func:`.diff.direction`'s. The socket's diff uses the same rows: no hidden value
leaves the vault in a diff, whichever way it is asked for (Y13).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Final, get_args, get_origin

from pydantic import TypeAdapter

from ..common.policy import schema
from ..common.policy.diff import BY_INDEX, NAME_SETS, Change, direction
from .display import NAME_LIMIT, shown
from .policyview import FIELDS, rendered

SET: Final = "(set)"
CHANGED: Final = "(changed)"
REMOVED: Final = "(removed)"
# The lists the diff compares item by item: a change to one of them carries one item.
_BY_ITEM: Final = NAME_SETS | BY_INDEX | {("Policy", "routes")}


def rows(changes: Iterable[Change]) -> list[dict[str, Any]]:
    """Each change as a row, in the diff's order."""
    return [_row(change) for change in changes]


def _row(change: Change) -> dict[str, Any]:
    treatment = FIELDS[change.model][change.field]
    if treatment in ("hidden", "names"):
        old, new = None, _marker(change)
    else:
        old = _shown(change, change.old, treatment)
        new = _shown(change, change.new, treatment)
    return {
        "path_shown": [_part(part) for part in change.path],
        "op": change.op,
        "direction": direction(change),
        "old": old,
        "new": new,
        "hidden": treatment != "shown",
    }


def _marker(change: Change) -> str:
    """That a hidden value was set, changed or removed, never the value."""
    if change.old is None:
        return SET
    return REMOVED if change.new is None else CHANGED


def _shown(change: Change, value: Any, treatment: Any) -> Any:
    """``value`` as the policy view shows the field (or one item of it) the change is under."""
    if value is None:
        return None
    adapter: TypeAdapter[Any] = TypeAdapter(_shape(change))
    return rendered(adapter.validate_python(value), treatment)


def _shape(change: Change) -> Any:
    """The type of a change's values: the field's own, or one entry's for a map, a route or a
    caller or rule by position, or a name in a set."""
    annotation = getattr(schema, change.model).model_fields[change.field].annotation
    if (change.model, change.field) in _BY_ITEM or get_origin(annotation) is dict:
        return get_args(annotation)[-1]
    return annotation


def _part(part: str | int) -> str | int:
    return shown(part, NAME_LIMIT) if isinstance(part, str) else part
