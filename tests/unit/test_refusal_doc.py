"""operations.md's portal troubleshooting table is the refusal catalogue's rendering (M5 M.2).

The table sits between two marker comments in ``docs/operations.md``; this test renders the
catalogue (``portal/refusals.py``) and checks the doc holds exactly that, byte for byte, so a
reason or text changed in one place and not the other fails here (verifier V42). To refresh the
doc after changing the catalogue, run ``python -m tests.unit.test_refusal_doc`` and paste its
output between the markers (on Windows, check the pasted lines end in LF only).
"""

from __future__ import annotations

import re
from pathlib import Path

from zoeymcp.portal.refusals import CATALOGUE, WEBAUTHN, enrolment

OPERATIONS = Path(__file__).resolve().parents[2] / "docs" / "operations.md"
BEGIN = "<!-- refusals: generated from portal/refusals.py; tests/unit/test_refusal_doc.py -->"
END = "<!-- end of refusals -->"


def _cell(text: str) -> str:
    """A catalogue text as a table cell: a field it fills in shows as ``<field>``."""
    return re.sub(r"\{(\w+)\}", r"`<\1>`", text).replace("|", "\\|")


def render() -> str:
    """The table: every catalogued reason, then every enrolment refusal (D.3), in the order the
    catalogue lists them."""
    rows = ["| Status | Reason | What the portal says |", "| --- | --- | --- |"]
    for reason, entry in CATALOGUE.items():
        rows.append(f"| {entry.status} | `{reason}` | {_cell(entry.text)} |")
    for reason, text in WEBAUTHN.items():
        status = enrolment(reason).status
        rows.append(f"| {status} | `{reason}` (enrolling a passkey) | {_cell(text)} |")
    return "\n".join(rows) + "\n"


def documented() -> str:
    text = OPERATIONS.read_bytes().decode("utf-8")
    _, begin, rest = text.partition(BEGIN + "\n")
    table, end, _ = rest.partition(END)
    assert begin, f"operations.md has no {BEGIN}"
    assert end, f"operations.md has no {END}"
    return table


def test_the_doc_is_the_catalogue() -> None:
    assert documented() == render()


def test_every_reason_is_a_row_once() -> None:
    reasons = re.findall(r"^\| \d{3} \| `([a-z_]+)`", render(), flags=re.MULTILINE)
    assert len(reasons) == len(CATALOGUE) + len(WEBAUTHN)
    assert set(reasons) == set(CATALOGUE) | set(WEBAUTHN)


def test_a_field_shows_as_its_name() -> None:
    assert _cell("uses store:{name}, so") == "uses store:`<name>`, so"
    assert _cell("a | b") == "a \\| b"


if __name__ == "__main__":
    print(render(), end="")
