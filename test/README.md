# Test suite

Two layers covering the watchtowr-mcp server:

- **Unit (`test/unit/`)** — 77 tests, no network, no credentials. Static checks that prove the SDK surface the MCP server imports actually exists, the `README.md` tool tables stay in lockstep with the `@mcp.tool()` registry, and the runtime patches in `sdk_compat.py` apply cleanly to real payload shapes.
- **Integration (`test/integration/`)** — 91 tests, one per documented MCP tool (88 tools; a few are parametrised). Calls every tool against a live watchTowr tenant and asserts the response is non-error. Skipped automatically when credentials are absent.

## Prerequisites

1. Submodule checked out:
   ```bash
   git submodule update --init --recursive
   ```
2. Dependencies installed (pulls pytest from the `dev` group):
   ```bash
   uv sync
   ```
3. For live tests, a tenant API key with read access (and a few resources in the tenant — at least one finding, one hunt, one domain, etc. — otherwise per-tool tests skip with a clear message).

## Running

### Unit tests (offline)

```bash
uv run pytest test/unit
```

Should always pass on any branch. If `test/unit/test_readme_sync.py` fails, the `README.md` tool tables have drifted from `watchtowr_mcp_server/tools/*.py` — the failure message names the divergent tool. If `test_sdk_surface.py` fails, an upstream SDK rename/removal has broken a call site in the MCP server.

### Live read-only sweep across all tools

```bash
WATCHTOWR_API_KEY="your-api-key" \
WATCHTOWR_PLATFORM_HOST="https://your-tenant.your-region.watchtowr.io" \
  uv run pytest test/integration -m live -v
```

This calls each list/detail/composite tool once with conservative defaults (`page_size=5`, `days=7–30`) and asserts no errors. Total runtime is dominated by network latency to the tenant — typically a few minutes.

### Include mutating tools (status flips, retests, seed asset, bulk ops)

```bash
WATCHTOWR_API_KEY=... WATCHTOWR_PLATFORM_HOST=... \
  uv run pytest test/integration -m live --run-writes
```

The `--run-writes` flag opts into 6 additional tests across `test_findings.py`, `test_assets_writes.py`, and `test_workflow.py`. These either round-trip a value (set status to its current value) or submit a clearly-marked test asset under `.invalid` so it never resolves.

### Run a single file or test

```bash
uv run pytest test/integration/test_findings.py -v
uv run pytest test/integration/test_findings.py::test_get_finding_details
uv run pytest test/integration/test_workflow.py -m write --run-writes
```

### CLI flags worth knowing

| Flag | Effect |
|------|--------|
| `-v` | one line per test (use this when debugging skips) |
| `-x` | stop at the first failure |
| `-k <pattern>` | run only tests whose name matches `<pattern>` |
| `-m live` | only tests marked `live` (the default for integration) |
| `-m "live and not write"` | reads only — same as default unless `--run-writes` is also passed |
| `--run-writes` | opt-in flag added by `conftest.py` to unblock `@pytest.mark.write` tests |

## Layout

```
test/
├── README.md                       ← you are here
├── conftest.py                     ← shared fixtures + --run-writes wiring
├── unit/
│   ├── test_sdk_surface.py         ← parametrised: every (Api class, method) the MCP imports
│   ├── test_readme_sync.py         ← parses README tables vs ast-walks tools/*.py
│   └── test_sdk_compat.py          ← exercises FindingRetestResponseDtoCompat + patched models
└── integration/
    ├── _helpers.py                 ← assert_ok() shared assertion
    ├── test_findings.py            ← 10 tools (8 reads + 2 writes, list-by-severity parametrised ×4)
    ├── test_assets_reads.py        ← 22 read tools across 10 asset types
    ├── test_assets_writes.py       ← update_asset_status, add_seed_asset (write-gated)
    ├── test_hunts.py               ← 6 tools
    ├── test_threat_intel.py        ← 6 tools
    ├── test_services.py            ← 2 tools
    ├── test_organization.py        ← 5 tools
    ├── test_composite.py           ← 13 cross-cutting tools
    ├── test_reporting.py           ← 11 reporting & compliance tools
    ├── test_incident.py            ← 5 incident response tools
    └── test_workflow.py            ← 6 tools (4 reads + 2 writes)
```

## Markers

| Marker | Purpose | Default behaviour |
|--------|---------|-------------------|
| `live` | needs `WATCHTOWR_API_KEY` + `WATCHTOWR_PLATFORM_HOST` | Auto-skip if env vars are missing. Applied to every integration test via module-level `pytestmark`. |
| `write` | mutates tenant state | Always skipped unless `--run-writes` is passed. Applied per-test on the 6 mutating tests. |

Both markers are declared in `pyproject.toml` under `[tool.pytest.ini_options]` with `--strict-markers`, so typos like `@pytest.mark.lvie` fail collection instead of silently no-op.

## Fixtures

Defined in `conftest.py`. All session-scoped so each one runs at most once per pytest invocation.

| Fixture | Type | What it gives you |
|---------|------|-------------------|
| `live_env` | guard | Skips the test if either credential env var is unset. Request this explicitly in every live test. |
| `tools` | `dict[str, Callable]` | Every `@mcp.tool()` function in the server, keyed by name. Built by registering against a `ToolCapture` shim that mimics FastMCP's decorator — no MCP transport needed. |
| `call` | `Callable[[str, **kwargs], Any]` | Sugar over `tools`. `call("list_findings_by_severity", severity="Critical", page_size=5)` invokes the underlying function directly. |
| `sample_<type>_id` | `int` | Real ID discovered by calling the matching `list_*` tool once and parsing the first `[ID:<n>]` out of the response. If the tenant has zero records of that type, the dependent test skips with a clear message — every other test continues. |

The 15 `sample_*_id` fixtures: `sample_finding_id`, `sample_hunt_id`, `sample_bu_id`, `sample_domain_id`, `sample_subdomain_id`, `sample_ip_id`, `sample_port_id`, `sample_iprange_id`, `sample_cert_id`, `sample_cloud_storage_id`, `sample_repo_id`, `sample_container_id`, `sample_saas_id`, `sample_mobile_id`, `sample_susp_domain_id`.

## How a test is structured

Every integration test follows the same shape:

```python
import pytest
from ._helpers import assert_ok

pytestmark = pytest.mark.live           # whole module needs creds

def test_list_findings_by_severity(live_env, call):
    assert_ok(call("list_findings_by_severity", severity="Critical", page_size=5),
              allow_empty=True)
```

`assert_ok` (in `integration/_helpers.py`) does three things:

1. Asserts the response is non-`None`.
2. Asserts it doesn't start with `"Error"` — every MCP tool wraps its body in `try/except` and returns `f"Error … {e}"` on failure, so that prefix is the canonical failure signal.
3. With `allow_empty=False` (the default) also asserts the response is non-empty. Pass `allow_empty=True` for tools that can legitimately return `"No X found."` against a sparsely-populated tenant.

For tools that return binary (e.g. `export_finding_pdf`), `assert_ok` checks for non-zero `len()` instead.

## Adding a new tool

When you add a new `@mcp.tool()` function:

1. Document it in the matching table in the root `README.md`. If you skip this, `test/unit/test_readme_sync.py::test_readme_and_code_tool_sets_match` fails with the missing tool name.
2. Bump the category heading count (`### Findings (10 tools)` → `(11 tools)`) — `test_category_tool_count_matches_readme_heading` enforces this.
3. If the tool calls a new SDK method, append the `(module, class, method)` triple to `SDK_CALLS` in `test/unit/test_sdk_surface.py` and bump the `len(SDK_CALLS)` assertion. The `test_sdk_calls_match_source` meta-test AST-walks the MCP source and fails if you skip this — the failure message names the exact triple to add.
4. Add a one-liner integration test:
   ```python
   def test_my_new_tool(live_env, call):
       assert_ok(call("my_new_tool", page_size=5), allow_empty=True)
   ```
5. If the new tool mutates state, mark it `@pytest.mark.write` and have it round-trip the value (set to current) so repeated runs don't drift tenant state.

## Troubleshooting

**All integration tests skip with "WATCHTOWR_API_KEY not set"** — `live_env` couldn't find the env var. Confirm with `echo $WATCHTOWR_API_KEY` in the same shell *before* `uv run pytest`. The `WATCHTOWR_API_KEY=... uv run pytest …` one-liner only works in bash/zsh — not when running through some IDE test runners.

**`test_sdk_surface.py` fails with `AttributeError`** — the submodule is checked out but the SDK was renamed/removed something the MCP imports. Either pull the submodule (`git submodule update --remote --merge`) or fix the call site.

**`test_readme_sync.py` fails** — your `tools/*.py` and `README.md` have drifted. The failure message names the missing tool on whichever side.

**`test_get_*_details` skips with "no X in this tenant"** — the corresponding `list_*` tool returned zero records, so there's no real ID to fetch details for. Not a bug — the suite is designed to degrade gracefully against under-populated tenants. Seed the tenant with at least one of that asset type to exercise the test.

**Live test fails with an `Error retrieving …` string** — `assert_ok` is reporting an error string the tool returned. The full error (HTTP status, server message) is in the response. Re-run with `-v` to see the full output.

**Write tests run when you didn't pass `--run-writes`** — they shouldn't. The gating is in `conftest.py::pytest_collection_modifyitems` and double-gated via the `@pytest.mark.write` marker. If you see this happen, check that you're using the pytest from the repo's venv (`uv run pytest`, not a globally-installed `pytest`).
