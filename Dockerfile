# syntax=docker/dockerfile:1
# Minimal image for Glama introspection: starts the MCP server over stdio.
# The tools/list introspection handshake needs no live Ollama endpoint credentials.
FROM python:3.12-slim

RUN pip install --no-cache-dir ai-guardian-aiops

# MCP server speaks JSON-RPC over stdio.
ENTRYPOINT ["ai-guardian-mcp"]
