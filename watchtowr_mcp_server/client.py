import functools
import inspect
import json
import logging
import os
import re
import secrets
import time
import typing
import unicodedata
from contextvars import ContextVar
from datetime import datetime, timezone

import urllib3
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_headers, get_http_request
from pydantic import ValidationError
from watchtowr_api_sdk import rest
from watchtowr_api_sdk.configuration import Configuration
from watchtowr_api_sdk.api_client import ApiClient
from watchtowr_api_sdk.exceptions import ApiException

from . import __version__
from .constants import FINDING_STATUSES
from .http_security import bearer_token

logger = logging.getLogger(__name__)

_api_client = None

mcp_request_headers: ContextVar[dict[str, str]] = ContextVar("mcp_request_headers", default={})
platform_stopped_answering: ContextVar[list[Exception] | None] = ContextVar("platform_stopped_answering", default=None)

READ_ONLY_ENV_VAR = "WATCHTOWR_MCP_READ_ONLY"
READ_ONLY_ON_VALUES = {"true", "1", "yes"}
READ_ONLY_OFF_VALUES = {"", "false", "0", "no"}
REQUEST_TIMEOUT_ENV_VAR = "WATCHTOWR_MCP_REQUEST_TIMEOUT"
ANYIO_WORKER_THREADS = 40
DEFAULT_REQUEST_TIMEOUT = 30.0
MAX_REQUEST_TIMEOUT = 600.0


class ReadOnlyModeError(RuntimeError):
    pass


class WriteRequestTimeoutError(urllib3.exceptions.ReadTimeoutError):
    pass


class WriteConnectionDroppedError(urllib3.exceptions.ProtocolError):
    pass


class PlatformStoppedAnsweringError(Exception):
    def __init__(self, rate_limited: bool):
        super().__init__()
        self.rate_limited = rate_limited


class PlatformRateLimitedError(Exception):
    pass


class UnexpectedPlatformResponseError(Exception):
    def __init__(self, model: str, fields: str | None = None):
        super().__init__(f"{model}: {fields}" if fields else model)


def env_value(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1].strip()
    return value


@functools.cache
def read_only_mode_enabled() -> bool:
    return env_value(READ_ONLY_ENV_VAR).lower() not in READ_ONLY_OFF_VALUES


def warn_if_read_only_value_is_unrecognised() -> None:
    value = env_value(READ_ONLY_ENV_VAR)
    if value.lower() not in READ_ONLY_ON_VALUES | READ_ONLY_OFF_VALUES:
        logger.warning(
            "%s=%r is not one of %s, so read-only mode is on and write tools are disabled.",
            READ_ONLY_ENV_VAR, value, ", ".join(sorted(READ_ONLY_ON_VALUES | READ_ONLY_OFF_VALUES - {""})),
        )


def read_only_error(refused: str) -> str:
    return (
        f"{refused} is refused because {READ_ONLY_ENV_VAR} is on; "
        "the MCP server only reads from the watchTowr Platform in read-only mode."
    )


def refuse_write_action_in_read_only_mode(action: str, read_action: str) -> None:
    if action != read_action and read_only_mode_enabled():
        raise ToolError(read_only_error(f"action {action!r}"))


_STATUS_HINTS = {
    400: "check the arguments",
    403: "the API key's role lacks permission for this",
    404: "check the ID",
    409: "it conflicts with the current state, re-read it and retry",
    422: "check the arguments",
    429: "rate limited, wait and retry",
}
UNREACHABLE_HINT = "cannot reach the watchTowr Platform - check WATCHTOWR_PLATFORM_HOST and network access"
WRITE_MAY_HAVE_HAPPENED = "the change may already have been made, check its current state before retrying"
PLATFORM_MESSAGE_STATUSES = {400, 422}
PLATFORM_MESSAGE_MAX_LENGTH = 200
_ADDITIONAL_RESPONSE_FIELD = re.compile(r"^Error due to additional fields \(not defined in (\w+)\) in the input: (.+)$")


def _unauthorized_hint() -> str:
    if serving_http():
        return "check the API key in the Authorization: Bearer header"
    return "check WATCHTOWR_API_KEY"


def _error_fields(e: ValidationError) -> str:
    return ", ".join(dict.fromkeys(str(error["loc"][0]) for error in e.errors() if error["loc"]))


def _argument_error_summary(e: ValidationError) -> str:
    problems = dict.fromkeys(
        f"{error['loc'][0]}: {error['msg'].removeprefix('Value error, ')}" if error["loc"] else error["msg"]
        for error in e.errors()
    )
    return f"invalid {'; '.join(problems)} - check the arguments"


def _tls_failure(e: Exception) -> str | None:
    if isinstance(e, urllib3.exceptions.MaxRetryError) and isinstance(e.reason, urllib3.exceptions.SSLError):
        return str(e.reason)
    if isinstance(e, urllib3.exceptions.SSLError):
        return str(e)
    if isinstance(e, ApiException) and e.status == 0 and (e.reason or "").startswith("SSLError\n"):
        return e.reason.split("\n", 1)[1]
    return None


def _connection_dropped(e: Exception) -> bool:
    if isinstance(e, urllib3.exceptions.MaxRetryError):
        e = e.reason
    return isinstance(e, urllib3.exceptions.ProtocolError)


def _platform_message(e: ApiException) -> str | None:
    if e.status not in PLATFORM_MESSAGE_STATUSES:
        return None
    try:
        message = json.loads(e.body or "").get("message")
    except (ValueError, AttributeError):
        return None
    if isinstance(message, list):
        message = "; ".join(str(part) for part in message)
    if not isinstance(message, str):
        return None
    message = " ".join(message.split())
    if not message:
        return None
    if len(message) > PLATFORM_MESSAGE_MAX_LENGTH:
        message = message[:PLATFORM_MESSAGE_MAX_LENGTH].rstrip() + "..."
    return message


def api_error_summary(e: Exception) -> str | None:
    if isinstance(e, PlatformStoppedAnsweringError):
        if e.rate_limited:
            return "skipped because the watchTowr Platform rate limited an earlier request in this tool call - wait and retry"
        return "skipped because an earlier request in this tool call got no answer from the watchTowr Platform"
    if isinstance(e, UnexpectedPlatformResponseError):
        return f"unexpected response from the watchTowr Platform ({e})"
    if isinstance(e, ValidationError):
        return _argument_error_summary(e)
    tls_failure = _tls_failure(e)
    if tls_failure is not None:
        return (
            f"TLS connection to the watchTowr Platform failed ({tls_failure}) - "
            "check WATCHTOWR_PLATFORM_HOST, and whether a proxy intercepts TLS"
        )
    if isinstance(e, WriteRequestTimeoutError):
        return f"no answer from the watchTowr Platform within {request_timeout():g} seconds - {WRITE_MAY_HAVE_HAPPENED}"
    if isinstance(e, WriteConnectionDroppedError):
        return f"the watchTowr Platform closed the connection without answering - {WRITE_MAY_HAVE_HAPPENED}"
    if isinstance(e, urllib3.exceptions.ReadTimeoutError):
        return (
            f"no answer from the watchTowr Platform within {request_timeout():g} seconds - "
            f"try a narrower query, or raise {REQUEST_TIMEOUT_ENV_VAR}"
        )
    if _connection_dropped(e):
        return "the watchTowr Platform closed the connection before the response was complete - retry"
    if isinstance(e, urllib3.exceptions.HTTPError):
        return UNREACHABLE_HINT
    if not isinstance(e, ApiException):
        return None
    status = e.status or 0
    if status == 0:
        return UNREACHABLE_HINT
    if status == 401:
        hint = _unauthorized_hint()
    else:
        hint = _STATUS_HINTS.get(status) or ("platform error, retry later" if status >= 500 else None)
    summary = f"HTTP {status} {e.reason or ''}".rstrip()
    platform_message = _platform_message(e)
    if platform_message:
        summary = f"{summary}: {platform_message}"
    return f"{summary} - {hint}" if hint else summary


def item_error_summary(e: Exception, item: str) -> str:
    summary = api_error_summary(e)
    if summary is None:
        logger.error("Unexpected error for %s", item, exc_info=e)
        return "unexpected error"
    return summary


def raise_tool_error(action: str, e: Exception) -> typing.NoReturn:
    if isinstance(e, ToolError):
        raise e
    summary = api_error_summary(e)
    if summary is not None:
        raise ToolError(f"Error {action}: {summary}") from None
    if isinstance(e, ReadOnlyModeError):
        raise ToolError(f"Error {action}: {e}") from None
    raise e


def parse_ids(value: str, name: str) -> list[int]:
    try:
        ids = [int(part.strip()) for part in value.split(",") if part.strip()]
    except ValueError as e:
        raise ToolError(f"{name} must be comma-separated integers, got {value!r}") from e
    if not ids:
        raise ToolError(f"{name} must contain at least one ID")
    return ids


@functools.cache
def request_timeout() -> float:
    raw = env_value(REQUEST_TIMEOUT_ENV_VAR)
    if not raw:
        return DEFAULT_REQUEST_TIMEOUT
    try:
        seconds = float(raw)
    except ValueError:
        seconds = 0.0
    if not 0 < seconds <= MAX_REQUEST_TIMEOUT:
        raise ToolError(
            f"{REQUEST_TIMEOUT_ENV_VAR} must be a number of seconds above 0 and at most "
            f"{MAX_REQUEST_TIMEOUT:g}, got {raw!r}"
        )
    return seconds


def _is_timeout(e: Exception | None) -> bool:
    return isinstance(e, urllib3.exceptions.TimeoutError) and not isinstance(
        e, urllib3.exceptions.NewConnectionError
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _read_body_within_timeout(response: rest.RESTResponse, url: str, timeout) -> None:
    seconds = timeout[1] if isinstance(timeout, tuple) else timeout
    deadline = time.monotonic() + seconds
    chunks = []
    while chunk := response.response.read1(65536):
        chunks.append(chunk)
        if time.monotonic() > deadline:
            response.response.close()
            raise urllib3.exceptions.ReadTimeoutError(
                None, url, f"Read timed out. (response body still arriving after {seconds:g} seconds)"
            )
    response.data = b"".join(chunks) if chunks else response.response.data


def _asks_to_back_off(response: rest.RESTResponse) -> bool:
    return response.status == 429 or (response.status == 503 and bool(response.getheader("Retry-After")))


class _NoTimeoutRetry(urllib3.Retry):
    """Default retries, except a timeout: each retry would wait the full timeout again."""

    def increment(self, method=None, url=None, response=None, error=None, _pool=None, _stacktrace=None):
        if _is_timeout(error):
            raise error
        return super().increment(method, url, response, error, _pool, _stacktrace)


class SecureApiClient(ApiClient):
    """ApiClient subclass that strips api_token from query parameters.

    The auto-generated SDK sends the API key as a query parameter for some
    endpoints. Query parameters are insecure — they appear in server access
    logs, proxy logs, and browser history. Bearer auth via the Authorization
    header (set through access_token) is used instead.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_agent = f"watchtowr-mcp/{__version__}"

    def param_serialize(self, method, resource_path, path_params=None,
                        query_params=None, header_params=None, body=None,
                        post_params=None, files=None, auth_settings=None,
                        collection_formats=None, _host=None,
                        _request_auth=None):
        if method.upper() != "GET" and read_only_mode_enabled():
            raise ReadOnlyModeError(read_only_error(f"{method} {resource_path}"))
        if query_params:
            query_params = [
                (k, v) for k, v in query_params if k != "api_token"
            ]
        return super().param_serialize(
            method, resource_path, path_params=path_params,
            query_params=query_params,
            header_params={**(header_params or {}), **mcp_request_headers.get()},
            body=body, post_params=post_params, files=files,
            auth_settings=auth_settings,
            collection_formats=collection_formats, _host=_host,
            _request_auth=_request_auth,
        )

    def call_api(self, method, url, header_params=None, body=None,
                 post_params=None, _request_timeout=None):
        stopped_answering = platform_stopped_answering.get()
        if stopped_answering:
            raise PlatformStoppedAnsweringError(rate_limited=isinstance(stopped_answering[0], PlatformRateLimitedError))
        timeout = request_timeout() if _request_timeout is None else _request_timeout
        is_write = method.upper() != "GET"
        try:
            response = super().call_api(
                method, url, header_params=header_params, body=body, post_params=post_params,
                _request_timeout=timeout,
            )
            _read_body_within_timeout(response, url, timeout)
            if stopped_answering is not None and _asks_to_back_off(response):
                stopped_answering.append(PlatformRateLimitedError())
            return response
        except (urllib3.exceptions.TimeoutError, urllib3.exceptions.MaxRetryError) as e:
            if stopped_answering is not None:
                stopped_answering.append(e)
            if is_write and isinstance(e, urllib3.exceptions.ReadTimeoutError):
                raise WriteRequestTimeoutError(e.pool, e.url, str(e).removeprefix(f"{e.pool}: ")) from None
            raise
        except urllib3.exceptions.ProtocolError as e:
            if is_write:
                raise WriteConnectionDroppedError(*e.args) from None
            raise

    def response_deserialize(self, response_data, response_types_map=None):
        try:
            return super().response_deserialize(response_data, response_types_map)
        except ValidationError as e:
            error = UnexpectedPlatformResponseError(e.title, _error_fields(e))
        except ValueError as e:
            match = _ADDITIONAL_RESPONSE_FIELD.match(str(e))
            if match is None:
                error = UnexpectedPlatformResponseError(str(response_types_map.get(str(response_data.status))))
            else:
                error = UnexpectedPlatformResponseError(match[1], match[2])
        logger.warning("Unexpected response from the watchTowr Platform: %s", error)
        raise error


def _platform_host() -> str:
    platform_host = env_value("WATCHTOWR_PLATFORM_HOST")
    if not platform_host:
        raise ToolError(
            "WATCHTOWR_PLATFORM_HOST environment variable not set. "
            "Expected format: https://your-tenant.your-region.client.watchtowr.io"
        )
    return platform_host


def _configuration(platform_host: str, api_key: str | None = None) -> Configuration:
    configuration = Configuration()
    configuration.host = platform_host
    configuration.access_token = api_key
    configuration.retries = _NoTimeoutRetry(
        urllib3.Retry.DEFAULT.total, allowed_methods=frozenset({"GET"}), respect_retry_after_header=False,
    )
    configuration.connection_pool_maxsize = ANYIO_WORKER_THREADS
    return configuration


@functools.cache
def _rest_client_for(platform_host: str) -> rest.RESTClientObject:
    return rest.RESTClientObject(_configuration(platform_host))


@functools.lru_cache(maxsize=64)
def _client_for(api_key: str, platform_host: str) -> ApiClient:
    api_client = SecureApiClient(_configuration(platform_host, api_key))
    api_client.rest_client = _rest_client_for(platform_host)
    return api_client


def serving_http() -> bool:
    if env_value("MCP_TRANSPORT") == "streamable-http":
        return True
    try:
        get_http_request()
    except RuntimeError:
        return False
    return True


def get_api_client() -> ApiClient:
    """Lazy initialization of API client - only called when tools are actually invoked.

    In streamable-http mode each request authenticates with the caller's own API key
    (Authorization: Bearer); the WATCHTOWR_API_KEY env var is never used there.
    """
    global _api_client

    if serving_http():
        headers = get_http_headers(include={"authorization"})
        api_key = bearer_token(headers.get("authorization"))
        if not api_key:
            raise ToolError("Missing Authorization: Bearer <watchTowr API key> header")
        return _client_for(api_key, _platform_host())

    if _api_client is not None:
        return _api_client

    api_key = env_value("WATCHTOWR_API_KEY")
    if not api_key:
        raise ToolError("WATCHTOWR_API_KEY environment variable not set")

    _api_client = _client_for(api_key, _platform_host())
    return _api_client


def get_total(response) -> int | None:
    """Extract pagination total from a paginated API response."""
    meta = getattr(response, 'meta', None)
    if meta:
        pagination = getattr(meta, 'pagination', None)
        if pagination:
            total = getattr(pagination, 'total', None)
            return int(total) if total is not None else None
    return None


def parse_date(date_str: str | None) -> datetime | None:
    """Parse an ISO-format date string into a datetime object."""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError as e:
        raise ToolError(f"Invalid date {date_str!r}: use ISO format, e.g. 2026-01-31") from e


def normalize_severities(value: str | None) -> str | None:
    """Normalize a comma-separated severities string for the watchTowr API.

    The API only accepts lowercase values ('critical', 'high', 'medium',
    'low', 'info'). Callers and users frequently pass title-case values
    like 'Critical' or 'High', which the API rejects with a 400
    "Severities not valid!" error. Lowercase the input and strip
    whitespace so the downstream call succeeds regardless of casing.
    """
    if not value:
        return value
    parts = [p.strip().lower() for p in value.split(",") if p.strip()]
    return ",".join(parts) if parts else None


def normalize_finding_status(status: str) -> str:
    normalized = status.lower().strip()
    if normalized not in FINDING_STATUSES:
        raise ToolError(f"Invalid status '{status}'. Valid: {', '.join(sorted(FINDING_STATUSES))}")
    return normalized


def severity_display(value) -> str:
    """Format an API severity value (lowercase) for user-facing display."""
    if not value:
        return "Unknown"
    return str(value).capitalize()


def format_bus(business_units) -> str:
    """Format a list of business unit model objects into a display string."""
    if not business_units:
        return ""
    names = [getattr(bu, 'name', 'Unknown') for bu in business_units]
    return f" [BU: {', '.join(names)}]"


_PORTAL_PATHS = {
    "finding": "findings/{id}",
    "hunt": "hunts/{id}/overview",
    "vulnerability": "ti/vulnerability-intelligence/{id}/overview",
    "adversary": "ti/adversary-intelligence/{id}/overview",
    "compromised_endpoint": "compromised-endpoints/{id}/overview",
    "business_unit": "organisation/business-unit/{id}",
    "port": "assets/ip/{id}/ports",
}

_PORTAL_ASSET_SEGMENTS = {
    "ip": "ip",
    "ipaddress": "ip",
    "domain": "domain",
    "subdomain": "subdomain",
    "iprange": "ip-range",
    "cloudstorage": "cloud-storage",
    "repository": "repository",
    "container": "container",
    "saasplatform": "saas-platform",
    "mobileapp": "mobile-app",
    "cloudasset": "cloud-asset",
    "apidocumentation": "api-documentation",
    "packagemanager": "package-manager",
}


def _portal_id(entity_id) -> int | None:
    entity_id = getattr(entity_id, "actual_instance", entity_id)
    if isinstance(entity_id, bool):
        return None
    if isinstance(entity_id, int):
        return entity_id if entity_id >= 0 else None
    if isinstance(entity_id, float):
        return int(entity_id) if entity_id.is_integer() and entity_id >= 0 else None
    if isinstance(entity_id, str) and entity_id.strip().isascii() and entity_id.strip().isdigit():
        return int(entity_id.strip())
    return None


def portal_url(kind: str, entity_id, asset_type: str | None = None) -> str | None:
    host = env_value("WATCHTOWR_PLATFORM_HOST").rstrip("/")
    portal_id = _portal_id(entity_id)
    if not host or portal_id is None:
        return None
    if kind == "asset":
        segment = _PORTAL_ASSET_SEGMENTS.get(re.sub(r"[\s_-]", "", str(asset_type or "")).lower())
        return f"{host}/assets/{segment}/{portal_id}/overview" if segment else None
    path = _PORTAL_PATHS.get(kind)
    return f"{host}/{path.format(id=portal_id)}" if path else None


def portal_link(kind: str, entity_id, asset_type: str | None = None, label: str | None = None) -> str:
    url = portal_url(kind, entity_id, asset_type)
    if not url:
        return ""
    return f" — {label}: {url}" if label else f" — {url}"


def portal_line(kind: str, entity_id, asset_type: str | None = None) -> list[str]:
    url = portal_url(kind, entity_id, asset_type)
    return [f"Portal: {url}"] if url else []


_HIDDEN_CHAR_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}
_UNTRUSTED_MARKER = re.compile("untrusted-data", re.IGNORECASE)


def _is_hidden(c: str) -> bool:
    return (
        unicodedata.category(c) in _HIDDEN_CHAR_CATEGORIES
        or "\ufe00" <= c <= "\ufe0f"
        or "\U000e0100" <= c <= "\U000e01ef"
    )


def untrusted(value, missing: str = "N/A") -> str:
    """Fence text that scanned internet hosts control, so the model reads it as data.

    The boundary ID is random per call and the tag name is neutralised inside the
    text, so it cannot forge an opening or closing tag. Hidden characters (control,
    zero-width, bidi, line/paragraph separators, private-use, variation selectors)
    are removed; newlines and tabs are kept. An absent value returns `missing`
    unfenced, since no host supplied it.
    """
    if value is None or value == "":
        return missing
    text = "".join(c for c in str(value) if c in "\n\t" or not _is_hidden(c))
    text = _UNTRUSTED_MARKER.sub("untrusted_data", text)
    tag = f"untrusted-data-{secrets.token_hex(8)}"
    return f"<{tag}>{text}</{tag}>"


def _expects_list(annotation) -> bool:
    """True if a parameter annotation ultimately wraps a list type.

    Asset list endpoints type `statuses`/`business_unit_ids` as
    Optional[List[str]] while the findings/certificates endpoints type the same
    filters as a comma-separated str. Inspect the annotation so a single helper
    can target both.
    """
    for sub in [annotation, *typing.get_args(annotation)]:
        if typing.get_origin(sub) in (list, typing.List):
            return True
        for arg in typing.get_args(sub):
            if typing.get_origin(arg) in (list, typing.List):
                return True
    return False


def accepts_argument(method, name: str) -> bool:
    parameters = inspect.signature(method).parameters
    return name in parameters or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values())


def supported_kwargs(method, kwargs: dict) -> dict:
    """Drop kwargs the SDK method doesn't declare and coerce list-typed ones.

    Asset list endpoints share most filters but differ on which they accept
    (e.g. PortsApi has no `statuses`) and on the type expected (asset endpoints
    want List[str] for `statuses`/`business_unit_ids`; findings/certs want a
    comma-separated str). Filtering + coercing here lets a single call site
    target every endpoint without crashing on the ones that disagree.
    """
    params = inspect.signature(method).parameters
    out = {}
    for k, v in kwargs.items():
        if k not in params:
            continue
        if isinstance(v, str) and _expects_list(params[k].annotation):
            out[k] = [part.strip() for part in v.split(",") if part.strip()]
        else:
            out[k] = v
    return out
