"""The self-test case file.

Example::

    cases:
      - name: a sandbox script reads stats
        request:
          method: GET
          path: /stats/2.0/?method=user.getinfo
          caller: {placeholder: ph-agent1-stats-4c1f9b27}
        expect:
          status: 200
          upstream:
            path: /2.0/
            query: {user: alice, method: user.getinfo}
            credential: true

      - name: a wrong placeholder reaches nothing
        request: {method: GET, path: /stats/2.0/, caller: {placeholder: guessed-value-0000}}
        expect: {status: 403}

``caller`` is ``gateway``, ``none``, or ``{placeholder: ...}``; a placeholder is presented where
the policy says that caller sends it (bearer, header or query), or as a bearer token if the
policy doesn't know it. ``expect.upstream`` is only valid for a forwarded request.
In ``query`` and ``headers``, ``null`` means "must be absent".
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..common.policy.schema import Method
from ..common.yamlload import load_mapping


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PlaceholderPresent(_Model):
    placeholder: Annotated[str, Field(min_length=1, max_length=256)]


class CaseRequest(_Model):
    method: Method
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    caller: Literal["gateway", "none"] | PlaceholderPresent = "none"
    headers: dict[str, str] = {}
    source: str = "172.30.4.10"
    body: str = ""


class UpstreamExpectation(_Model):
    method: Method | None = None
    path: str | None = None
    query: dict[str, str | None] = {}
    headers: dict[str, str | None] = {}
    credential: bool | None = None


class Expectation(_Model):
    status: Annotated[int, Field(ge=100, le=599)]
    upstream: UpstreamExpectation | None = None

    @model_validator(mode="after")
    def _upstream_needs_success(self) -> Expectation:
        if self.upstream is not None and self.status >= 400:
            raise ValueError("expect.upstream needs a forwarded request (status below 400)")
        return self


class Case(_Model):
    name: Annotated[str, Field(min_length=1, max_length=200)]
    request: CaseRequest
    expect: Expectation


class CaseFile(_Model):
    cases: Annotated[list[Case], Field(min_length=1)]


def parse_cases(text: str) -> CaseFile:
    return CaseFile.model_validate(load_mapping(text))
