"""MCP server exposing read-only navigation tools over an OKF knowledge bundle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from google_okf.bundle import Bundle, Concept

INSTRUCTIONS = """\
Read-only access to an OKF knowledge bundle (schemas, APIs, metrics, policies, runbooks).
1. Call get_index first to find the domain relevant to the query.
2. Use read_concept and get_links to follow the knowledge graph; search when the path is unknown.
3. Call recent_changes before relying on a schema, since log.md records breaking changes.
This bundle holds structural knowledge only. It contains no tenant data, and any live
query you build from it must still be scoped to the authenticated tenant_id.
"""

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)


def _get(b: Bundle, path: str) -> Concept:
    """Look up a concept, surfacing unknown paths to the agent as a tool error rather than a crash."""
    try:
        return b.get(path)
    except KeyError as exc:
        raise ToolError(exc.args[0]) from None


def create_server(root: Path) -> MCPServer:
    root = Path(root).resolve()
    server = MCPServer(name="okf-bundle", instructions=INSTRUCTIONS)

    # Reloaded per call so edits to the bundle are visible without a restart.
    def bundle() -> Bundle:
        return Bundle.load(root)

    @server.tool(annotations=READ_ONLY)
    def get_index() -> dict[str, Any]:
        """Bundle entry point: title, description, the index entries with summaries, and the index guide."""
        b = bundle()
        entries = [b.get(e).summary() if e in b.concepts else {"path": e, "missing": True}
                   for e in b.index_meta.get("entries", [])]
        return {
            "title": b.index_meta.get("title", ""),
            "description": b.index_meta.get("description", ""),
            "okf_version": b.index_meta.get("okf_version", ""),
            "entries": entries,
            "guide": b.index_body,
        }

    @server.tool(annotations=READ_ONLY)
    def list_concepts(type: str | None = None) -> list[dict[str, str]]:
        """List concepts (path, type, title, description), optionally filtered by type, e.g. 'table' or 'metric'."""
        return [c.summary() for c in bundle().concepts.values() if type is None or c.type == type]

    @server.tool(annotations=READ_ONLY)
    def read_concept(path: str) -> dict[str, Any]:
        """Read one concept's frontmatter and Markdown body by bundle-relative path, e.g. 'tables/tenants.md'."""
        c = _get(bundle(), path)
        return {"path": c.path, "frontmatter": c.meta, "body": c.body}

    @server.tool(annotations=READ_ONLY)
    def get_links(path: str) -> dict[str, Any]:
        """Outgoing links from a concept and backlinks pointing to it, for traversing the knowledge graph."""
        b = bundle()
        c = _get(b, path)
        return {"path": c.path, "outgoing": c.links, "backlinks": b.backlinks(c.path)}

    @server.tool(annotations=READ_ONLY)
    def search(query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Keyword search (all terms must match) over concept titles, descriptions, tags and bodies."""
        return bundle().search(query, limit)

    @server.tool(annotations=READ_ONLY)
    def recent_changes(since: str | None = None) -> list[dict[str, Any]]:
        """Change log entries, newest first. Optional 'since' (YYYY-MM-DD) keeps entries on or after that date."""
        return [e for e in bundle().log if since is None or e["date"] >= since]

    return server
