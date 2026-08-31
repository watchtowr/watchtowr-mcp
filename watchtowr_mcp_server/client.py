import inspect
import os
import typing
from datetime import datetime

from watchtowr_api_sdk.configuration import Configuration
from watchtowr_api_sdk.api_client import ApiClient

_api_client = None


class SecureApiClient(ApiClient):
    """ApiClient subclass that strips api_token from query parameters.

    The auto-generated SDK sends the API key as a query parameter for some
    endpoints. Query parameters are insecure — they appear in server access
    logs, proxy logs, and browser history. Bearer auth via the Authorization
    header (set through access_token) is used instead.
    """

    def param_serialize(self, method, resource_path, path_params=None,
                        query_params=None, header_params=None, body=None,
                        post_params=None, files=None, auth_settings=None,
                        collection_formats=None, _host=None,
                        _request_auth=None):
        if query_params:
            query_params = [
                (k, v) for k, v in query_params if k != "api_token"
            ]
        return super().param_serialize(
            method, resource_path, path_params=path_params,
            query_params=query_params, header_params=header_params,
            body=body, post_params=post_params, files=files,
            auth_settings=auth_settings,
            collection_formats=collection_formats, _host=_host,
            _request_auth=_request_auth,
        )


def get_api_client() -> ApiClient:
    """Lazy initialization of API client - only called when tools are actually invoked."""
    global _api_client

    if _api_client is not None:
        return _api_client

    api_key = os.environ.get("WATCHTOWR_API_KEY")
    platform_host = os.environ.get("WATCHTOWR_PLATFORM_HOST")

    if not api_key:
        raise RuntimeError("WATCHTOWR_API_KEY environment variable not set")

    if not platform_host:
        raise RuntimeError(
            "WATCHTOWR_PLATFORM_HOST environment variable not set. "
            "Expected format: https://your-tenant.your-region.watchtowr.io"
        )

    configuration = Configuration()
    configuration.host = platform_host
    configuration.access_token = api_key

    _api_client = SecureApiClient(configuration)
    return _api_client


def get_total(response) -> int | None:
    """Extract pagination total from a paginated API response."""
    meta = getattr(response, 'meta', None)
    if meta:
        pagination = getattr(meta, 'pagination', None)
        if pagination:
            return getattr(pagination, 'total', None)
    return None


def parse_date(date_str: str | None) -> datetime | None:
    """Parse an ISO-format date string into a datetime object."""
    if not date_str:
        return None
    return datetime.fromisoformat(date_str.replace("Z", "+00:00"))


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
