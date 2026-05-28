"""Auth-template grammar, parsing, and rendering.

An auth_template maps an HTTP header name to a value containing ``{placeholder}``
references, substituted from a credential mapping (e.g.
``{"Authorization": "Bearer {token}"}``). Shared by external-app credential
resolution (``onyx.db.external_app``) and the proxy's credential injection; kept
free of mitmproxy/DB imports so either side can use it without pulling heavy
dependencies.
"""

import re
from collections.abc import Mapping

PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class TemplateRenderError(Exception):
    """An auth_template referenced a placeholder absent from the values."""


def placeholders_in_template(auth_template: Mapping[str, object]) -> set[str]:
    """The set of ``{placeholder}`` names referenced across the template's values."""
    placeholders: set[str] = set()
    for value in auth_template.values():
        if isinstance(value, str):
            placeholders.update(PLACEHOLDER_RE.findall(value))
    return placeholders


def render_auth_template(
    auth_template: Mapping[str, str], values: Mapping[str, str]
) -> dict[str, str]:
    """Render each header value via ``{placeholder}`` substitution.

    A placeholder with no corresponding value raises ``TemplateRenderError``
    rather than emitting a half-formed auth header. Extra ``values`` are ignored.
    """
    rendered: dict[str, str] = {}
    for header, template in auth_template.items():
        missing = set(PLACEHOLDER_RE.findall(template)) - set(values.keys())
        if missing:
            raise TemplateRenderError(
                f"auth_template header {header!r} is missing values for "
                f"{sorted(missing)}"
            )
        try:
            rendered[header] = template.format_map(values)
        except (KeyError, ValueError, IndexError) as e:
            raise TemplateRenderError(
                f"auth_template header {header!r} could not be rendered: {e}"
            ) from e
    return rendered
