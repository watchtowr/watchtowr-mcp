"""Shared assertions for integration tests.

Tool failures raise `ToolError`, which fails the test on its own. `assert_ok`
checks the response is a usable, non-empty result so per-tool tests stay
one-liners.
"""
from __future__ import annotations


def assert_ok(response, *, allow_empty: bool = False) -> None:
    """Assert the tool returned a usable result. Pass `allow_empty=True` for tools
    that can legitimately return "No X found." against an empty tenant."""
    assert response is not None, "tool returned None"
    if isinstance(response, (bytes, bytearray)):
        assert len(response) > 0, "binary response was empty"
        return
    assert isinstance(response, str), f"expected str, got {type(response).__name__}"
    if not allow_empty:
        assert response, "tool returned an empty string"
