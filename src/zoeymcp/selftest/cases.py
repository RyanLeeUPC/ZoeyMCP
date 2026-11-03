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

      - name: an order waits for the operator
        request:
          method: POST
          path: /broker/mcp
          caller: gateway
          headers: {content-type: application/json, mcp-protocol-version: "2025-11-25"}
          body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"place_order"}}'
        expect: {held: true}

``caller`` is ``gateway``, ``none``, or ``{placeholder: ...}``; a placeholder is presented where
the policy says that caller sends it (bearer, header or query), or as a bearer token if the
policy doesn't know it. ``expect.upstream`` is only valid for a forwarded request.
In ``query`` and ``headers``, ``null`` means "must be absent".

``expect`` is a ``status``, or ``held: true`` for a call the vault holds for an approval (M8
design I.5): the call is held and shown once, nothing reaches the upstream, and the self-test
withdraws it, so it never answers with a status of its own.
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
    status: Annotated[int, Field(ge=100, le=599)] | None = None
    held: bool = False
    upstream: UpstreamExpectation | None = None

    @model_validator(mode="after")
    def _status_or_held(self) -> Expectation:
        if self.held and self.status is not None:
            raise ValueError("expect.held is the outcome: a held call answers no status")
        if not self.held and self.status is None:
            raise ValueError("expect needs a status, or held: true")
        if self.upstream is not None and (self.status is None or self.status >= 400):
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
