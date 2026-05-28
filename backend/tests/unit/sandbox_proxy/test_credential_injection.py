"""Unit tests for the credential-injection dispatcher.

Shared stubs/factories (`make_flow`, `make_resolved_sandbox`, `FakeResolver`,
`StubResolver`) live in conftest. Grammar/render tests live in
tests/unit/onyx/external_apps/test_auth_template.py.
"""

from __future__ import annotations

import pytest
from mitmproxy import http

from onyx.sandbox_proxy.credential_injection import CredentialInjectionDispatcher
from onyx.sandbox_proxy.credential_injection import Injection
from onyx.sandbox_proxy.credential_injection import INJECTION_HANDLED_FLAG
from onyx.sandbox_proxy.credential_injection import InjectionOutcome
from tests.unit.sandbox_proxy.conftest import FakeResolver
from tests.unit.sandbox_proxy.conftest import make_flow
from tests.unit.sandbox_proxy.conftest import make_resolved_sandbox
from tests.unit.sandbox_proxy.conftest import StubResolver


def test_no_resolver_match_passes_through_without_resolving_identity() -> None:
    identity = StubResolver(sandbox=make_resolved_sandbox())
    resolver = FakeResolver(host="api.openai.com")
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = make_flow(host="registry.npmjs.org", headers={"Authorization": "keep"})

    assert dispatcher.apply(flow) is InjectionOutcome.PASS_THROUGH
    assert identity.resolve_sandbox_calls == 0
    assert resolver.resolve_calls == []
    assert flow.request.headers == {"Authorization": "keep"}
    assert INJECTION_HANDLED_FLAG not in flow.metadata


def test_match_overwrites_named_headers_leaving_others_intact() -> None:
    sandbox = make_resolved_sandbox(tenant_id="tenant_acme")
    identity = StubResolver(sandbox=sandbox)
    resolver = FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "Bearer real-key"}),
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = make_flow(
        host="api.openai.com",
        headers={"Authorization": "Bearer placeholder", "Accept": "application/json"},
    )

    assert dispatcher.apply(flow) is InjectionOutcome.INJECTED
    # Overwritten (set/replace, not appended), other headers untouched.
    assert flow.request.headers == {
        "Authorization": "Bearer real-key",
        "Accept": "application/json",
    }
    assert flow.metadata[INJECTION_HANDLED_FLAG] is True
    # Resolver received the identity resolved from the source IP.
    assert resolver.resolve_calls == [sandbox]


def test_resolver_returns_none_fails_closed() -> None:
    identity = StubResolver(sandbox=make_resolved_sandbox())
    resolver = FakeResolver(host="api.openai.com", injection=None)
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = make_flow(host="api.openai.com", headers={"Authorization": "placeholder"})

    assert dispatcher.apply(flow) is InjectionOutcome.BLOCKED
    assert flow.metadata[INJECTION_HANDLED_FLAG] is True
    assert flow.request.headers == {"Authorization": "placeholder"}


@pytest.mark.parametrize(
    "identity",
    [
        StubResolver(sandbox=None),
        StubResolver(sandbox_exc=RuntimeError("db down")),
    ],
    ids=["unidentified", "db_error"],
)
def test_owned_host_with_unresolvable_identity_fails_closed(
    identity: StubResolver,
) -> None:
    resolver = FakeResolver(
        host="api.openai.com", injection=Injection(headers={"Authorization": "x"})
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = make_flow(host="api.openai.com")

    assert dispatcher.apply(flow) is InjectionOutcome.BLOCKED
    assert resolver.resolve_calls == []
    assert flow.metadata[INJECTION_HANDLED_FLAG] is True


def test_resolver_exception_fails_closed_without_raising() -> None:
    identity = StubResolver(sandbox=make_resolved_sandbox())
    resolver = FakeResolver(host="api.openai.com", resolve_exc=RuntimeError("boom"))
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = make_flow(host="api.openai.com")

    assert dispatcher.apply(flow) is InjectionOutcome.BLOCKED
    assert flow.metadata[INJECTION_HANDLED_FLAG] is True


def test_first_matching_resolver_wins() -> None:
    identity = StubResolver(sandbox=make_resolved_sandbox())
    first = FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "from-first"}),
    )
    second = FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "from-second"}),
    )
    dispatcher = CredentialInjectionDispatcher(
        resolvers=[first, second], identity=identity
    )
    flow = make_flow(host="api.openai.com")

    assert dispatcher.apply(flow) is InjectionOutcome.INJECTED
    assert flow.request.headers["Authorization"] == "from-first"
    assert second.resolve_calls == []


def test_no_source_ip_on_owned_host_fails_closed() -> None:
    identity = StubResolver(sandbox=make_resolved_sandbox())
    resolver = FakeResolver(
        host="api.openai.com", injection=Injection(headers={"Authorization": "x"})
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = make_flow(host="api.openai.com", peername=None)

    assert dispatcher.apply(flow) is InjectionOutcome.BLOCKED
    assert identity.resolve_sandbox_calls == 0
    assert flow.metadata[INJECTION_HANDLED_FLAG] is True


def test_overwrite_on_real_headers_replaces_case_insensitively() -> None:
    # The dict-based flow can't surface append-vs-replace or case bugs; the real
    # mitmproxy Headers type can. Incoming header is lowercase, injected is not.
    identity = StubResolver(sandbox=make_resolved_sandbox())
    resolver = FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "Bearer real"}),
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = make_flow(host="api.openai.com")
    flow.request.headers = http.Headers([(b"authorization", b"Bearer placeholder")])

    assert dispatcher.apply(flow) is InjectionOutcome.INJECTED
    # Single value, replaced (not appended), matched case-insensitively.
    assert flow.request.headers.get_all("Authorization") == ["Bearer real"]


def test_match_exception_falls_through_to_next_resolver() -> None:
    identity = StubResolver(sandbox=make_resolved_sandbox())
    raising = FakeResolver(
        host="api.openai.com", match_exc=RuntimeError("bad host check")
    )
    good = FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "real"}),
    )
    dispatcher = CredentialInjectionDispatcher(
        resolvers=[raising, good], identity=identity
    )
    flow = make_flow(host="api.openai.com")

    assert dispatcher.apply(flow) is InjectionOutcome.INJECTED
    assert flow.request.headers["Authorization"] == "real"


def test_injects_all_headers_in_a_multi_header_template() -> None:
    identity = StubResolver(sandbox=make_resolved_sandbox())
    resolver = FakeResolver(
        host="api.anthropic.com",
        injection=Injection(
            headers={"x-api-key": "secret", "anthropic-version": "2023-06-01"}
        ),
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = make_flow(host="api.anthropic.com", headers={"x-api-key": "placeholder"})

    assert dispatcher.apply(flow) is InjectionOutcome.INJECTED
    assert flow.request.headers["x-api-key"] == "secret"
    assert flow.request.headers["anthropic-version"] == "2023-06-01"
