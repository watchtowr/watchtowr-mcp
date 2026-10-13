from mcp.server.transport_security import TransportSecurityMiddleware, TransportSecuritySettings
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import Response

DEFAULT_ALLOWED_HOSTS = (
    "127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*", "[::1]", "[::1]:*",
)
DEFAULT_ALLOWED_ORIGINS = ("http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*")


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    return token if scheme.lower() == "bearer" and token else None


class HttpSecurityMiddleware:
    def __init__(self, app, settings: TransportSecuritySettings):
        self.app = app
        self.transport_security = TransportSecurityMiddleware(settings)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        response = await self.transport_security.validate_request(request, is_post=False)
        if response is None and not bearer_token(request.headers.get("authorization")):
            response = Response(
                "Missing bearer token", status_code=401, headers={"WWW-Authenticate": "Bearer"}
            )
        if response is not None:
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def _env_list(name: str, default: tuple[str, ...]) -> list[str]:
    from .client import env_value  # client imports this module at load time

    value = env_value(name)
    if not value:
        return list(default)
    return [part.strip() for part in value.split(",") if part.strip()]


def build_http_middleware() -> list[Middleware]:
    settings = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_env_list("MCP_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS),
        allowed_origins=_env_list("MCP_ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS),
    )
    return [Middleware(HttpSecurityMiddleware, settings=settings)]
