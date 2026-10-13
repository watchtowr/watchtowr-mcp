from fastmcp.server.context import Context
from fastmcp.server.middleware import Middleware

from .client import mcp_request_headers, platform_stopped_answering

MAX_MCP_CLIENT_HEADER_LENGTH = 256


def _sendable_mcp_client_name_and_version(fastmcp_context: Context | None) -> str | None:
    if fastmcp_context is None or fastmcp_context.request_context is None:
        return None
    client_params = fastmcp_context.session.client_params
    if client_params is None:
        return None
    client_info = client_params.clientInfo
    mcp_client = f"{client_info.name}/{client_info.version}"
    if (
        mcp_client.isascii()
        and mcp_client.isprintable()
        and len(mcp_client) <= MAX_MCP_CLIENT_HEADER_LENGTH
    ):
        return mcp_client
    return None


class RequestHeadersMiddleware(Middleware):
    async def on_call_tool(self, context, call_next):
        headers = {"X-Watchtowr-MCP-Tool": context.message.name}
        mcp_client = _sendable_mcp_client_name_and_version(context.fastmcp_context)
        if mcp_client is not None:
            headers["X-Watchtowr-MCP-Client"] = mcp_client
        headers_token = mcp_request_headers.set(headers)
        stopped_answering_token = platform_stopped_answering.set([])
        try:
            return await call_next(context)
        finally:
            platform_stopped_answering.reset(stopped_answering_token)
            mcp_request_headers.reset(headers_token)
