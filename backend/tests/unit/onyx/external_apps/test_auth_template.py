"""Unit tests for the shared auth_template grammar, parsing, and rendering."""

from __future__ import annotations

import pytest

from onyx.external_apps.auth_template import placeholders_in_template
from onyx.external_apps.auth_template import render_auth_template
from onyx.external_apps.auth_template import TemplateRenderError

# ---------------------------------------------------------------------------
# placeholders_in_template
# ---------------------------------------------------------------------------


def test_placeholders_unions_references_across_values() -> None:
    found = placeholders_in_template(
        {"Authorization": "Bearer {token}", "X-Account": "{account}"}
    )
    assert found == {"token", "account"}


def test_placeholders_skips_non_string_values() -> None:
    # auth_template values come from JSONB and may be non-strings; those are
    # skipped rather than raising.
    assert placeholders_in_template({"X": "{token}", "Y": 5, "Z": None}) == {"token"}


def test_placeholders_empty_when_no_references() -> None:
    assert placeholders_in_template({"X-Const": "literal"}) == set()


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
    # These slip past the placeholder regex but make format_map raise; the wrap
    # must surface TemplateRenderError, not a raw ValueError/KeyError/IndexError.
    with pytest.raises(TemplateRenderError):
        render_auth_template({"Authorization": template}, {"key": "x"})
