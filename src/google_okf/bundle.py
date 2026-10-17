"""Read-only loader for an OKF knowledge bundle (index.md, log.md, concept files)."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

RESERVED = ("index.md", "log.md")
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
LOG_DATE_RE = re.compile(r"^##\s+(\d{4}-\d{2}-\d{2})\s*$")


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Return (frontmatter, body). Files without a leading '---' block have empty frontmatter."""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return {}, text
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            meta = yaml.safe_load("\n".join(lines[1:i])) or {}
            return meta, "\n".join(lines[i + 1 :]).lstrip("\n")
    return {}, text


def normalize(path: str) -> str:
    """Normalize a bundle-relative path ('./tables/x.md' -> 'tables/x.md')."""
    return posixpath.normpath(path.replace("\\", "/").lstrip("/"))


@dataclass
class Concept:
    path: str
    meta: dict[str, Any]
    body: str
    links: list[str] = field(default_factory=list)

    @property
    def type(self) -> str:
        return str(self.meta.get("type", ""))

    @property
    def title(self) -> str:
        return str(self.meta.get("title", self.path))

    @property
    def description(self) -> str:
        return str(self.meta.get("description", ""))

    def summary(self) -> dict[str, str]:
        return {"path": self.path, "type": self.type, "title": self.title, "description": self.description}


@dataclass
class Bundle:
    root: Path
    index_meta: dict[str, Any]
    index_body: str
    concepts: dict[str, Concept]
    log: list[dict[str, Any]]

    @classmethod
    def load(cls, root: Path) -> Bundle:
        root = Path(root)
        index_text = (root / "index.md").read_text(encoding="utf-8")
        index_meta, index_body = split_frontmatter(index_text)

        concepts: dict[str, Concept] = {}
        for file in sorted(root.rglob("*.md")):
            rel = file.relative_to(root).as_posix()
            if rel in RESERVED:
                continue
            meta, body = split_frontmatter(file.read_text(encoding="utf-8"))
            concepts[rel] = Concept(rel, meta, body, _links(rel, body))

        log_file = root / "log.md"
        log = _parse_log(log_file.read_text(encoding="utf-8")) if log_file.exists() else []
        return cls(root, index_meta, index_body, concepts, log)

    def get(self, path: str) -> Concept:
        concept = self.concepts.get(normalize(path))
        if concept is None:
            raise KeyError(f"Unknown concept '{path}'. Use list_concepts to see valid paths.")
        return concept

    def backlinks(self, path: str) -> list[str]:
        target = self.get(path).path
        return [c.path for c in self.concepts.values() if target in c.links]

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        terms = [t for t in query.lower().split() if t]
        if not terms:
            return []
        hits = []
        for c in self.concepts.values():
            head = f"{c.title} {c.description} {' '.join(map(str, c.meta.get('tags', [])))}".lower()
            body = c.body.lower()
            if not all(t in head or t in body for t in terms):
                continue
            score = sum(3 * head.count(t) + body.count(t) for t in terms)
            hits.append({**c.summary(), "score": score, "snippet": _snippet(c.body, terms[0])})
        hits.sort(key=lambda h: (-h["score"], h["path"]))
        return hits[:limit]


def _links(rel: str, body: str) -> list[str]:
    """Resolve relative Markdown links to bundle-relative paths, de-duplicated in order."""
    out: list[str] = []
    base = posixpath.dirname(rel)
    for target in LINK_RE.findall(body):
        target = target.split("#", 1)[0]
        if not target or SCHEME_RE.match(target):
            continue
        resolved = posixpath.normpath(posixpath.join(base, target))
        if not resolved.startswith("..") and resolved not in out:
            out.append(resolved)
    return out


def _parse_log(text: str) -> list[dict[str, Any]]:
    """Parse '## YYYY-MM-DD' sections and their '* ' bullets, newest first."""
    entries: list[dict[str, Any]] = []
    for line in text.split("\n"):
        line = line.rstrip()
        if m := LOG_DATE_RE.match(line):
            entries.append({"date": m.group(1), "changes": []})
        elif entries and line.lstrip().startswith(("* ", "- ")):
            entries[-1]["changes"].append(line.lstrip()[2:])
    entries.sort(key=lambda e: e["date"], reverse=True)
    return entries


def _snippet(body: str, term: str, width: int = 80) -> str:
    i = body.lower().find(term)
    if i < 0:
        return body[: 2 * width].replace("\n", " ").strip()
    start = max(0, i - width)
    return ("…" if start else "") + body[start : i + width].replace("\n", " ").strip() + "…"
