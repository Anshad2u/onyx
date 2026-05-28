"""Unit tests for the credential-injection seam (dispatcher + renderer).

Resolvers and the identity lookup are stubbed; flows are MagicMock'd like the
GateAddon suite. Per-resolver behavior is exercised by each resolver's own tests.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import UUID
from uuid import uuid4

import pytest
from mitmproxy import http

from onyx.external_apps.auth_template import render_auth_template
from onyx.external_apps.auth_template import TemplateRenderError
from onyx.sandbox_proxy.credential_injection import CredentialInjectionDispatcher
from onyx.sandbox_proxy.credential_injection import Injection
from onyx.sandbox_proxy.credential_injection import INJECTION_HANDLED_FLAG
from onyx.sandbox_proxy.credential_injection import InjectionOutcome
from onyx.sandbox_proxy.identity import ResolvedSandbox


class _FakeResolver:
    def __init__(
        self,
        *,
        host: str,
        injection: Injection | None = None,
        resolve_exc: Exception | None = None,
        match_exc: Exception | None = None,
    ) -> None:
        self._host = host
        self._injection = injection
        self._resolve_exc = resolve_exc
        self._match_exc = match_exc
        self.resolve_calls: list[ResolvedSandbox] = []

    def matches_host(self, host: str) -> bool:
        if self._match_exc is not None:
            raise self._match_exc
        return host == self._host

    def resolve(
        self,
        request: http.Request,  # noqa: ARG002
        identity: ResolvedSandbox,
    ) -> Injection | None:
        self.resolve_calls.append(identity)
        if self._resolve_exc is not None:
            raise self._resolve_exc
        return self._injection


class _FakeIdentity:
    def __init__(
        self, *, sandbox: ResolvedSandbox | None = None, exc: Exception | None = None
    ) -> None:
        self._sandbox = sandbox
        self._exc = exc
        self.calls = 0

    def resolve_sandbox(self, src_ip: str) -> ResolvedSandbox | None:  # noqa: ARG002
        self.calls += 1
        if self._exc is not None:
            raise self._exc
        return self._sandbox


def _sandbox(tenant_id: str = "public") -> ResolvedSandbox:
    return ResolvedSandbox(
        sandbox_id=UUID("11111111-1111-1111-1111-111111111111"),
        user_id=uuid4(),
        tenant_id=tenant_id,
        sandbox_name="sandbox-aaaa1111",
        sandbox_ip="10.0.0.1",
    )


def _flow(
    *,
    host: str = "api.openai.com",
    peername: tuple[str, int] | None = ("10.0.0.1", 12345),
    headers: dict[str, str] | None = None,
) -> http.HTTPFlow:
    flow = MagicMock(spec=http.HTTPFlow)
    flow.client_conn = MagicMock()
    flow.client_conn.peername = peername
    flow.request = MagicMock()
    flow.request.host = host
    flow.request.headers = dict(headers) if headers is not None else {}
    flow.response = None
    flow.metadata = {}
    return flow


# ---------------------------------------------------------------------------
# render_auth_template
# ---------------------------------------------------------------------------


def test_render_substitutes_placeholder() -> None:
    rendered = render_auth_template(
        {"Authorization": "Bearer {key}"}, {"key": "sk-123"}
    )
    assert rendered == {"Authorization": "Bearer sk-123"}


def test_render_passes_through_literal_values_and_ignores_extra_values() -> None:
    rendered = render_auth_template(
        {"x-api-key": "{key}", "anthropic-version": "2023-06-01"},
        {"key": "secret", "unused": "x"},
    )
    assert rendered == {"x-api-key": "secret", "anthropic-version": "2023-06-01"}


def test_render_fails_closed_on_missing_placeholder() -> None:
    with pytest.raises(TemplateRenderError):
        render_auth_template({"Authorization": "Bearer {key}"}, {})


@pytest.mark.parametrize("template", ["Bearer {", "Bearer {0}", "Bearer {bad-name}"])
def test_render_wraps_malformed_template_as_template_render_error(
    template: str,
) -> None:
    # These slip past the placeholder regex but make format_map raise; the
    # wrap must surface TemplateRenderError, not a raw ValueError/KeyError.
    with pytest.raises(TemplateRenderError):
        render_auth_template({"Authorization": template}, {"key": "x"})


# ---------------------------------------------------------------------------
# dispatcher
# ---------------------------------------------------------------------------


def test_no_resolver_match_passes_through_without_resolving_identity() -> None:
    identity = _FakeIdentity(sandbox=_sandbox())
    resolver = _FakeResolver(host="api.openai.com")
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = _flow(host="registry.npmjs.org", headers={"Authorization": "keep"})

    assert dispatcher.apply(flow) is InjectionOutcome.PASS_THROUGH
    assert identity.calls == 0
    assert resolver.resolve_calls == []
    assert flow.request.headers == {"Authorization": "keep"}
    assert INJECTION_HANDLED_FLAG not in flow.metadata


def test_match_overwrites_named_headers_leaving_others_intact() -> None:
    sandbox = _sandbox(tenant_id="tenant_acme")
    identity = _FakeIdentity(sandbox=sandbox)
    resolver = _FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "Bearer real-key"}),
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = _flow(
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
    identity = _FakeIdentity(sandbox=_sandbox())
    resolver = _FakeResolver(host="api.openai.com", injection=None)
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = _flow(host="api.openai.com", headers={"Authorization": "placeholder"})

    assert dispatcher.apply(flow) is InjectionOutcome.BLOCKED
    assert flow.metadata[INJECTION_HANDLED_FLAG] is True
    assert flow.request.headers == {"Authorization": "placeholder"}


@pytest.mark.parametrize(
    "identity",
    [
        _FakeIdentity(sandbox=None),
        _FakeIdentity(exc=RuntimeError("db down")),
    ],
    ids=["unidentified", "db_error"],
)
def test_owned_host_with_unresolvable_identity_fails_closed(
    identity: _FakeIdentity,
) -> None:
    resolver = _FakeResolver(
        host="api.openai.com", injection=Injection(headers={"Authorization": "x"})
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = _flow(host="api.openai.com")

    assert dispatcher.apply(flow) is InjectionOutcome.BLOCKED
    assert resolver.resolve_calls == []
    assert flow.metadata[INJECTION_HANDLED_FLAG] is True


def test_resolver_exception_fails_closed_without_raising() -> None:
    identity = _FakeIdentity(sandbox=_sandbox())
    resolver = _FakeResolver(host="api.openai.com", resolve_exc=RuntimeError("boom"))
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = _flow(host="api.openai.com")

    assert dispatcher.apply(flow) is InjectionOutcome.BLOCKED
    assert flow.metadata[INJECTION_HANDLED_FLAG] is True


def test_first_matching_resolver_wins() -> None:
    identity = _FakeIdentity(sandbox=_sandbox())
    first = _FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "from-first"}),
    )
    second = _FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "from-second"}),
    )
    dispatcher = CredentialInjectionDispatcher(
        resolvers=[first, second], identity=identity
    )
    flow = _flow(host="api.openai.com")

    assert dispatcher.apply(flow) is InjectionOutcome.INJECTED
    assert flow.request.headers["Authorization"] == "from-first"
    assert second.resolve_calls == []


def test_no_source_ip_on_owned_host_fails_closed() -> None:
    identity = _FakeIdentity(sandbox=_sandbox())
    resolver = _FakeResolver(
        host="api.openai.com", injection=Injection(headers={"Authorization": "x"})
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = _flow(host="api.openai.com", peername=None)

    assert dispatcher.apply(flow) is InjectionOutcome.BLOCKED
    assert identity.calls == 0
    assert flow.metadata[INJECTION_HANDLED_FLAG] is True


def test_overwrite_on_real_headers_replaces_case_insensitively() -> None:
    # The dict-based flow can't surface append-vs-replace or case bugs; the real
    # mitmproxy Headers type can. Incoming header is lowercase, injected is not.
    identity = _FakeIdentity(sandbox=_sandbox())
    resolver = _FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "Bearer real"}),
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = _flow(host="api.openai.com")
    flow.request.headers = http.Headers([(b"authorization", b"Bearer placeholder")])

    assert dispatcher.apply(flow) is InjectionOutcome.INJECTED
    # Single value, replaced (not appended), matched case-insensitively.
    assert flow.request.headers.get_all("Authorization") == ["Bearer real"]


def test_match_exception_falls_through_to_next_resolver() -> None:
    identity = _FakeIdentity(sandbox=_sandbox())
    raising = _FakeResolver(
        host="api.openai.com", match_exc=RuntimeError("bad host check")
    )
    good = _FakeResolver(
        host="api.openai.com",
        injection=Injection(headers={"Authorization": "real"}),
    )
    dispatcher = CredentialInjectionDispatcher(
        resolvers=[raising, good], identity=identity
    )
    flow = _flow(host="api.openai.com")

    assert dispatcher.apply(flow) is InjectionOutcome.INJECTED
    assert flow.request.headers["Authorization"] == "real"


def test_injects_all_headers_in_a_multi_header_template() -> None:
    identity = _FakeIdentity(sandbox=_sandbox())
    resolver = _FakeResolver(
        host="api.anthropic.com",
        injection=Injection(
            headers={"x-api-key": "secret", "anthropic-version": "2023-06-01"}
        ),
    )
    dispatcher = CredentialInjectionDispatcher(resolvers=[resolver], identity=identity)
    flow = _flow(host="api.anthropic.com", headers={"x-api-key": "placeholder"})

    assert dispatcher.apply(flow) is InjectionOutcome.INJECTED
    assert flow.request.headers["x-api-key"] == "secret"
    assert flow.request.headers["anthropic-version"] == "2023-06-01"
