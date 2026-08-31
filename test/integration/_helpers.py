"""Shared assertions for integration tests.

Every MCP tool wraps its body in `try: ... except Exception as e: return f"Error
... {e}"`. A live test passes when the response is a non-empty string that
*doesn't* start with that prefix. `assert_ok` centralises that check so per-tool
tests stay one-liners.
"""
from __future__ import annotations


def assert_ok(response, *, allow_empty: bool = False) -> None:
    """Assert the tool didn't error. Pass `allow_empty=True` for tools that
    can legitimately return "No X found." against an empty tenant."""
    assert response is not None, "tool returned None"
    if isinstance(response, (bytes, bytearray)):
        assert len(response) > 0, "binary response was empty"
        return
    assert isinstance(response, str), f"expected str, got {type(response).__name__}"
    if not allow_empty:
        assert response, "tool returned an empty string"
    if response.startswith("Error"):
        raise AssertionError(f"tool returned an error: {response[:300]}")
