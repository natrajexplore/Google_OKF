import asyncio
from pathlib import Path

import pytest
from mcp import Client

from google_okf.bundle import Bundle, split_frontmatter
from google_okf.server import create_server

REAL_BUNDLE = Path(__file__).resolve().parents[1] / "shieldpulse-okf"


@pytest.fixture
def bundle_dir(tmp_path: Path) -> Path:
    (tmp_path / "tables").mkdir()
    (tmp_path / "index.md").write_text(
        '---\ntitle: "Test"\nentries:\n  - tables/a.md\n  - tables/gone.md\n---\n# Index\n', encoding="utf-8"
    )
    (tmp_path / "log.md").write_text(
        "# Log\n\n## 2026-01-01\n* Old change\n\n## 2026-03-01\n* New change\n- Dash bullet\n", encoding="utf-8"
    )
    (tmp_path / "tables" / "a.md").write_text(
        '---\r\ntype: table\r\ntitle: "alpha"\r\ntags: ["billing"]\r\n---\r\n'
        "Links [b](./b.md#cols), [b again](b.md), [ext](https://x.io/a.md), [self](#top), [out](../../etc.md).\r\n",
        encoding="utf-8",
    )
    (tmp_path / "tables" / "b.md").write_text("---\ntype: metric\ntitle: beta\n---\nRevenue alpha body.\n", encoding="utf-8")
    return tmp_path


def call(root: Path, tool: str, args: dict | None = None):
    async def run():
        async with Client(create_server(root)) as client:
            return await client.call_tool(tool, args or {})

    return asyncio.run(run())


def test_split_frontmatter_without_block():
    assert split_frontmatter("no frontmatter") == ({}, "no frontmatter")


def test_load_parses_crlf_frontmatter_and_resolves_links(bundle_dir: Path):
    b = Bundle.load(bundle_dir)
    a = b.get("./tables/a.md")
    assert (a.type, a.title) == ("table", "alpha")
    # fragment stripped, de-duplicated; external, same-page and out-of-bundle links dropped
    assert a.links == ["tables/b.md"]
    assert b.backlinks("tables/b.md") == ["tables/a.md"]
    assert set(b.concepts) == {"tables/a.md", "tables/b.md"}


def test_unknown_or_traversal_path_rejected(bundle_dir: Path):
    b = Bundle.load(bundle_dir)
    for bad in ("tables/missing.md", "../index.md", "index.md"):
        with pytest.raises(KeyError):
            b.get(bad)


def test_search_requires_all_terms_and_ranks_title_hits(bundle_dir: Path):
    b = Bundle.load(bundle_dir)
    assert [h["path"] for h in b.search("alpha")] == ["tables/a.md", "tables/b.md"]
    assert [h["path"] for h in b.search("revenue alpha")] == ["tables/b.md"]
    assert [h["path"] for h in b.search("billing")] == ["tables/a.md"]
    assert b.search("   ") == []


def test_log_parsed_newest_first(bundle_dir: Path):
    log = Bundle.load(bundle_dir).log
    assert [e["date"] for e in log] == ["2026-03-01", "2026-01-01"]
    assert log[0]["changes"] == ["New change", "Dash bullet"]


def test_server_tools_end_to_end(bundle_dir: Path):
    index = call(bundle_dir, "get_index").structured_content
    assert index["title"] == "Test"
    assert index["entries"][1] == {"path": "tables/gone.md", "missing": True}

    tables = call(bundle_dir, "list_concepts", {"type": "table"}).structured_content["result"]
    assert [c["path"] for c in tables] == ["tables/a.md"]

    links = call(bundle_dir, "get_links", {"path": "tables/b.md"}).structured_content
    assert links == {"path": "tables/b.md", "outgoing": [], "backlinks": ["tables/a.md"]}

    changes = call(bundle_dir, "recent_changes", {"since": "2026-02-01"}).structured_content["result"]
    assert [e["date"] for e in changes] == ["2026-03-01"]


def test_server_reports_bad_path_as_tool_error(bundle_dir: Path):
    result = call(bundle_dir, "read_concept", {"path": "../index.md"})
    assert result.is_error
    assert "Unknown concept '../index.md'" in result.content[0].text


def test_real_bundle_is_fully_linked():
    b = Bundle.load(REAL_BUNDLE)
    assert sorted(b.index_meta["entries"]) == sorted(b.concepts)
    for c in b.concepts.values():
        assert c.type, c.path
        assert all(link in b.concepts or link in ("index.md", "log.md") for link in c.links), c.path
    assert "tables/policy_drift_events.md" in b.backlinks("tables/tenants.md")
