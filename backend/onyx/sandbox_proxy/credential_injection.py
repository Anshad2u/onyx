"""The egress credential-injection seam: one dispatcher, many resolvers.

A ``CredentialResolver`` claims the outbound hosts it owns and renders the auth
header(s) the proxy overwrites on the request, so long-lived secrets live only
in the proxy and never in the sandbox pod. The dispatcher runs from the gate's
``requestheaders`` hook: the first resolver whose ``matches_host`` claims the
host wins, identity is resolved once, and the rendered headers are overwritten
on the request. A claimed host whose credential can't be produced fails closed.
With no resolvers registered every flow is ``PASS_THROUGH`` and identity is
never resolved.
"""

import enum
from dataclasses import dataclass
from typing import Protocol

from mitmproxy import http

from onyx.sandbox_proxy.identity import extract_src_ip
from onyx.sandbox_proxy.identity import ResolvedSandbox
from onyx.sandbox_proxy.identity import SandboxResolver
from onyx.utils.logger import setup_logger

logger = setup_logger()

# Set once injection has handled a flow (injected or blocked); the ``request``
# hook reads it to skip the gating path.
INJECTION_HANDLED_FLAG = "onyx_credential_injection_handled"


@dataclass(frozen=True)
class Injection:
    """Auth headers to overwrite on the outbound request.

    set/replace, never append; headers not named here are left intact.
    """

    headers: dict[str, str]


class CredentialResolver(Protocol):
    """Resolves a credential for the outbound hosts it owns."""

    def matches_host(self, host: str) -> bool:
        """Cheap, no-DB check: does this resolver own ``host``? First match wins."""
        ...

    def resolve(
        self, request: http.Request, identity: ResolvedSandbox
    ) -> Injection | None:
        """Render the headers to inject, or ``None`` to fail closed.

        Called only after ``matches_host`` returned True, so ``None`` means the
        host is owned but its credential can't be produced — the dispatcher
        blocks rather than forwarding without the secret.
        """
        ...


class InjectionOutcome(enum.Enum):
    PASS_THROUGH = "pass_through"
    INJECTED = "injected"
    BLOCKED = "blocked"


class CredentialInjectionDispatcher:
    """Ordered resolver list + first-host-match dispatch. ``apply`` never raises."""

    def __init__(
        self,
        resolvers: list[CredentialResolver],
        identity: SandboxResolver,
    ) -> None:
        self._resolvers = list(resolvers)
        self._identity = identity

    def apply(self, flow: http.HTTPFlow) -> InjectionOutcome:
        host = flow.request.host or ""
        resolver = self._match(host)
        if resolver is None:
            return InjectionOutcome.PASS_THROUGH

        src_ip = extract_src_ip(flow)
        if src_ip is None:
            return self._block(flow, host=host, identity=None, reason="no_source_ip")
        try:
            identity = self._identity.resolve_sandbox(src_ip)
        except Exception:
            logger.exception("gate.injection_identity_error host=%s", host)
            return self._block(flow, host=host, identity=None, reason="identity_error")
        if identity is None:
            return self._block(
                flow, host=host, identity=None, reason="unidentified_sandbox"
            )

        resolver_name = type(resolver).__name__
        try:
            injection = resolver.resolve(flow.request, identity)
        except Exception:
            logger.exception(
                "gate.injection_resolver_error host=%s sandbox_id=%s "
                "tenant_id=%s resolver=%s",
                host,
                identity.sandbox_id,
                identity.tenant_id,
                resolver_name,
            )
            return self._block(
                flow, host=host, identity=identity, reason="resolver_error"
            )
        if injection is None:
            return self._block(flow, host=host, identity=identity, reason="unresolved")

        for name, value in injection.headers.items():
            flow.request.headers[name] = value
        flow.metadata[INJECTION_HANDLED_FLAG] = True
        logger.info(
            "gate.credential_injected host=%s sandbox_id=%s tenant_id=%s "
            "resolver=%s headers=%s",
            host,
            identity.sandbox_id,
            identity.tenant_id,
            resolver_name,
            sorted(injection.headers.keys()),
        )
        return InjectionOutcome.INJECTED

    def _match(self, host: str) -> CredentialResolver | None:
        for resolver in self._resolvers:
            try:
                if resolver.matches_host(host):
                    return resolver
            except Exception:
                logger.exception(
                    "gate.injection_match_error host=%s resolver=%s",
                    host,
                    type(resolver).__name__,
                )
        return None

    def _block(
        self,
        flow: http.HTTPFlow,
        *,
        host: str,
        identity: ResolvedSandbox | None,
        reason: str,
    ) -> InjectionOutcome:
        flow.metadata[INJECTION_HANDLED_FLAG] = True
        logger.warning(
            "gate.credential_block host=%s sandbox_id=%s tenant_id=%s reason=%s",
            host,
            identity.sandbox_id if identity is not None else None,
            identity.tenant_id if identity is not None else None,
            reason,
        )
        return InjectionOutcome.BLOCKED


def build_resolvers() -> list[CredentialResolver]:
    """The ordered resolver list the dispatcher tries first-match-by-host.

    Empty until resolvers register here; an empty list makes the seam inert.
    """
    return []
