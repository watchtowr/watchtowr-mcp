FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/watchtowr/watchtowr-mcp"

WORKDIR /app

COPY pyproject.toml uv.lock ./
# Use the watchtowr-api-sdk submodule checked out on the host (pinned commit),
# instead of cloning the SDK's latest main, so the image matches the repo's pin.
COPY watchtowr-api-sdk/ watchtowr-api-sdk/
RUN uv sync && uv pip install -e watchtowr-api-sdk

COPY watchtowr_mcp_server/ watchtowr_mcp_server/
RUN uv pip install -e .

ENV PORT=8080
EXPOSE $PORT

CMD ["uv", "run", "watchtowr-mcp"]
