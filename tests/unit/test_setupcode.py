"""Setup codes (M5 design E): the code, the typed form, the MAC'd record, the redeem decision."""

from __future__ import annotations

import hashlib
import hmac
import io
from base64 import b32encode
from typing import Any

import pytest
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from zoeymcp.common import logs as common_logs
from zoeymcp.common.canonical import dumps_canonical
from zoeymcp.portal.setupcode import (
    CODE_BYTES,
    CODE_CHARS,
    FILE,
    GROUP,
    MAX_FILE_BYTES,
    MAX_TYPED,
    TTL,
    VERSION,
    Record,
    Redeemed,
    Refused,
    SetupCode,
    decide,
    digest,
    group,
    new_code,
    new_record,
    normalize,
    seal,
    unseal,
)
from zoeymcp.vault import logs
from zoeymcp.vault.keys import CONTEXT_PORTAL, KeySet, derive

MASTER = bytes(range(32))
KEY = KeySet.from_master(MASTER).portal_key
OTHER = KeySet.from_master(bytes(range(1, 33))).portal_key
RAW = bytes(range(15))
# b32encode(bytes(range(15))), grouped.
CODE = "AAAQEA-YEAUDA-OCAJBI-FQYDIO"
NOW = 1_760_000_000.7
SHA = hashlib.sha256(CODE.encode()).hexdigest()


def test_the_constants() -> None:
    assert (FILE, VERSION, TTL) == ("setup.json", 1, 900)
    assert (CODE_BYTES, CODE_CHARS, GROUP) == (15, 24, 6)
    assert (MAX_TYPED, MAX_FILE_BYTES) == (64, 4096)


# --- the code -----------------------------------------------------------------------------------


def test_a_code_is_fifteen_random_bytes_in_four_groups() -> None:
    asked: list[int] = []

    def random(n: int) -> bytes:
        asked.append(n)
        return RAW

    code = new_code(random)
    assert asked == [15]
    assert code.reveal() == CODE
    assert b32encode(RAW).decode() == CODE.replace("-", "")


def test_group() -> None:
    assert group("ABCDEFGHIJKLMNOPQRSTUVWX") == "ABCDEF-GHIJKL-MNOPQR-STUVWX"


def test_a_code_hides_itself() -> None:
    code = SetupCode(CODE)
    assert repr(code) == "SetupCode(<hidden>)"
    assert str(code) == "SetupCode(<hidden>)"
    assert f"{code}" == "SetupCode(<hidden>)"
    assert CODE not in repr([code])


def test_a_code_is_refused_by_the_logger() -> None:
    assert SetupCode in common_logs.refused_types()
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        for value in (SetupCode(CODE), [SetupCode(CODE)], {"a": (SetupCode(CODE),)}):
            with pytest.raises(TypeError, match=r"\(SetupCode\) in field 'f'"):
                logs.event("oops", f=value)
    finally:
        logs.set_stream(None)
    assert buffer.getvalue() == ""


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        (CODE, CODE),
        (CODE.lower(), CODE),
        (CODE.replace("-", ""), CODE),
        (CODE.replace("-", " "), CODE),
        ("  " + CODE.replace("-", " - ").lower() + "  ", CODE),
        ("aaaq-eaye-audaoc-ajbifq-ydio", CODE),
        ("A" * 24, "AAAAAA-AAAAAA-AAAAAA-AAAAAA"),
        ("2" * 24, "222222-222222-222222-222222"),
        ("7" * 24, "777777-777777-777777-777777"),
        ("Z" * 24, "ZZZZZZ-ZZZZZZ-ZZZZZZ-ZZZZZZ"),
        # Up to 64 characters are read; more are wrong whatever they hold.
        (CODE + " " * (64 - len(CODE)), CODE),
        (CODE + " " * (65 - len(CODE)), None),
        ("-" * 40 + CODE.replace("-", ""), CODE),
        ("-" * 41 + CODE.replace("-", ""), None),
        # Exactly 24 base32 characters.
        (CODE[:-1], None),
        (CODE + "A", None),
        ("", None),
        ("-", None),
        # Outside the alphabet: 0, 1, 8, 9 and punctuation.
        (CODE[:-1] + "0", None),
        (CODE[:-1] + "1", None),
        (CODE[:-1] + "8", None),
        (CODE[:-1] + "9", None),
        (CODE[:-1] + "=", None),
        (CODE[:-1] + "_", None),
        # Other separators aren't dropped.
        (CODE.replace("-", "\t"), None),
        (CODE.replace("-", "_"), None),
        (CODE.replace("-", "\n"), None),
        (CODE + "\n", None),
        # Only ASCII: a dotless i upper-cases into I, and full-width letters aren't letters here.
        (chr(0x131) * 24, None),
        (chr(0xFF21) * 24, None),
        (CODE.replace("-", chr(0x2010)), None),
        (None, None),
        (24, None),
        (["A" * 24], None),
        (b"A" * 24, None),
    ],
)
def test_normalize(typed: object, expected: str | None) -> None:
    assert normalize(typed) == expected


def test_digest_is_the_sha256_of_the_grouped_form() -> None:
    assert digest(CODE) == SHA
    assert digest(CODE) != hashlib.sha256(CODE.replace("-", "").encode()).hexdigest()


def test_new_record() -> None:
    assert new_record(SetupCode(CODE), now=NOW, reset=False) == Record(SHA, 1_760_000_900, False)
    assert new_record(SetupCode(CODE), now=NOW, reset=True) == Record(SHA, 1_760_000_900, True)


def test_a_record_hides_its_hash() -> None:
    record = Record(SHA, 1, True)
    assert SHA not in repr(record)
    assert repr(record) == "Record(expires=1, reset=True)"


# --- the record file ----------------------------------------------------------------------------


def _mac(content: dict[str, Any], master: bytes = MASTER) -> str:
    key = derive(master, CONTEXT_PORTAL)
    message = b"zoeymcp/setup-code/v1\n" + dumps_canonical(content)
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def content(**changes: Any) -> dict[str, Any]:
    made: dict[str, Any] = {
        "v": 1,
        "key_id": KEY.key_id,
        "sha256": SHA,
        "expires": 1_760_000_900,
        "reset": False,
    }
    made.update(changes)
    return made


def signed(rest: dict[str, Any], master: bytes = MASTER) -> bytes:
    return dumps_canonical({**rest, "mac": _mac(rest, master)}) + b"\n"


def test_seal_format() -> None:
    data = seal(Record(SHA, 1_760_000_900, True), KEY)
    rest = content(reset=True)
    expected = (
        b'{"expires":1760000900,"key_id":"'
        + KEY.key_id.encode()
        + b'","mac":"'
        + _mac(rest).encode()
        + b'","reset":true,"sha256":"'
        + SHA.encode()
        + b'","v":1}\n'
    )
    assert data == expected
    assert CODE.encode() not in data


def test_unseal_reads_what_seal_wrote() -> None:
    for record in (Record(SHA, 0, False), Record("0" * 64, 2**40, True)):
        assert unseal(seal(record, KEY), KEY) == record


def test_unseal_reads_a_record_sealed_independently() -> None:
    assert unseal(signed(content()), KEY) == Record(SHA, 1_760_000_900, False)


def test_another_master_key_is_no_code() -> None:
    assert unseal(seal(Record(SHA, 1, False), OTHER), KEY) is None
    # Even with this master's key ID, the MAC is another key's.
    assert unseal(signed(content(), bytes(range(1, 33))), KEY) is None


def test_a_planted_record_is_no_code() -> None:
    """A writer of /state without the master key can't plant a code it knows (T16)."""
    planted = content(sha256=hashlib.sha256(b"KNOWN0-KNOWN0-KNOWN0-KNOWN0").hexdigest())
    for mac in ("0" * 64, _mac(content()), "", 0, None):
        assert unseal(dumps_canonical({**planted, "mac": mac}), KEY) is None


def test_every_changed_byte_is_no_code() -> None:
    data = seal(Record(SHA, 1_760_000_900, False), KEY)
    for index in range(len(data) - 1):
        changed = bytearray(data)
        changed[index] ^= 0x01
        assert unseal(bytes(changed), KEY) is None, index


def test_a_record_from_before_m5_is_no_code() -> None:
    assert unseal(b'{"sha256":"' + SHA.encode() + b'","expires":1760000900}', KEY) is None


def test_the_size_limit() -> None:
    data = seal(Record(SHA, 1, False), KEY)
    at_limit = data + b" " * (MAX_FILE_BYTES - len(data))
    assert unseal(at_limit, KEY) == Record(SHA, 1, False)
    assert unseal(at_limit + b" ", KEY) is None


@pytest.mark.parametrize(
    "data", [b"", b"not json", b"[]", b'"x"', b"1", b"null", b'{"v":1', b"\xff\xfe"]
)
def test_what_isnt_a_record_is_no_code(data: bytes) -> None:
    assert unseal(data, KEY) is None


@pytest.mark.parametrize(
    "shape",
    [
        {name: value for name, value in content().items() if name != "reset"},
        {**content(), "extra": 1},
        {**content(), "code": CODE},
    ],
    ids=["missing", "extra", "code"],
)
def test_another_shape_is_no_code(shape: dict[str, Any]) -> None:
    assert unseal(signed(shape), KEY) is None


@pytest.mark.parametrize(
    ("field", "value", "ok"),
    [
        ("v", 1, True),
        ("v", 2, False),
        ("v", 0, False),
        ("v", True, False),
        ("v", 1.0, False),
        ("v", "1", False),
        ("key_id", "0" * 16, False),
        ("key_id", None, False),
        ("sha256", "0" * 64, True),
        ("sha256", "f" * 64, True),
        ("sha256", "0" * 63, False),
        ("sha256", "0" * 65, False),
        ("sha256", "A" * 64, False),
        ("sha256", "g" * 64, False),
        ("sha256", 0, False),
        ("sha256", None, False),
        ("expires", 0, True),
        ("expires", -1, False),
        ("expires", 1.5, False),
        ("expires", True, False),
        ("expires", "1760000900", False),
        ("expires", None, False),
        ("reset", True, True),
        ("reset", 1, False),
        ("reset", 0, False),
        ("reset", "true", False),
        ("reset", None, False),
    ],
)
def test_each_field_is_checked(field: str, value: Any, ok: bool) -> None:
    rest = content(**{field: value})
    assert (unseal(signed(rest), KEY) is not None) is ok


def test_a_mac_that_isnt_text_is_no_code() -> None:
    rest = content()
    for mac in (None, 1, [_mac(rest)], {"mac": _mac(rest)}):
        assert unseal(dumps_canonical({**rest, "mac": mac}), KEY) is None


# --- the decision -------------------------------------------------------------------------------

RECORD = Record(SHA, 1_760_000_900, False)


def test_the_code_redeems_until_its_second() -> None:
    assert decide(RECORD, CODE, NOW) == Redeemed(1_760_000_900, False)
    assert decide(RECORD, CODE, 1_760_000_899.999) == Redeemed(1_760_000_900, False)
    assert decide(RECORD, CODE, 1_760_000_900) == Refused("expired")
    assert decide(RECORD, CODE, 1_760_000_901) == Refused("expired")


def test_reset_is_carried() -> None:
    assert decide(Record(SHA, 1_760_000_900, True), CODE, NOW) == Redeemed(1_760_000_900, True)


def test_the_typed_form_is_normalized_first() -> None:
    assert decide(RECORD, CODE.lower().replace("-", " "), NOW) == Redeemed(1_760_000_900, False)


@pytest.mark.parametrize(
    "typed",
    [
        "AAAQEA-YEAUDA-OCAJBI-FQYDIA",
        CODE[:-1],
        "",
        None,
        SHA,
        CODE + " " * 64,
    ],
)
def test_a_wrong_code_is_refused(typed: object) -> None:
    assert decide(RECORD, typed, NOW) == Refused("wrong")
    # Wrong comes before expired: a late wrong code says nothing about the right one.
    assert decide(RECORD, typed, 2_000_000_000) == Refused("wrong")


def test_no_record_is_no_code() -> None:
    assert decide(None, CODE, NOW) == Refused("no_code")
    assert decide(None, "", NOW) == Refused("no_code")


# --- a code redeems at most once, and never after it expires -----------------------------------


class SetupMachine(RuleBasedStateMachine):
    """The record file as SetupCodes keeps it: written on issue, removed on a redemption."""

    def __init__(self) -> None:
        super().__init__()
        self.now = NOW
        self.file: bytes | None = None
        self.counter = 0
        # Every code issued: its text, its expiry, and whether it redeemed.
        self.issued: list[tuple[str, int]] = []
        self.redeemed: set[str] = set()

    def _random(self, n: int) -> bytes:
        self.counter += 1
        return self.counter.to_bytes(n, "big")

    @rule(reset=st.booleans())
    def issue(self, reset: bool) -> None:
        code = new_code(self._random)
        record = new_record(code, now=self.now, reset=reset)
        self.file = seal(record, KEY)
        self.issued.append((code.reveal(), record.expires))

    @precondition(lambda self: bool(self.issued))
    @rule(data=st.data(), spelling=st.sampled_from(["as-is", "lower", "spaced"]))
    def redeem(self, data: st.DataObject, spelling: str) -> None:
        code, expires = data.draw(st.sampled_from(self.issued))
        typed = {"as-is": code, "lower": code.lower(), "spaced": code.replace("-", " ")}[spelling]
        record = None if self.file is None else unseal(self.file, KEY)
        decision = decide(record, typed, self.now)
        latest = self.issued[-1][0]
        if isinstance(decision, Redeemed):
            assert code == latest
            assert code not in self.redeemed
            assert self.now < expires
            self.redeemed.add(code)
            self.file = None
        else:
            assert code != latest or code in self.redeemed or self.now >= expires

    @rule(typed=st.text(max_size=30))
    def guess(self, typed: str) -> None:
        record = None if self.file is None else unseal(self.file, KEY)
        assert isinstance(decide(record, typed, self.now), Refused)

    @rule(step=st.sampled_from([0.5, 1.0, 60.0, 899.0, 900.0, 3600.0]))
    def wait(self, step: float) -> None:
        self.now += step

    @invariant()
    def at_most_one_code_works(self) -> None:
        record = None if self.file is None else unseal(self.file, KEY)
        works = [
            code for code, _ in self.issued if isinstance(decide(record, code, self.now), Redeemed)
        ]
        assert len(works) <= 1
        assert not set(works) & self.redeemed


TestSetupMachine = SetupMachine.TestCase
TestSetupMachine.settings = hypothesis_settings(
    max_examples=50, stateful_step_count=20, deadline=None
)
