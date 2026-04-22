"""RSS-based threat intelligence feeds.

Polls public RSS sources (Rekt.news, CVE) and normalises each entry into
a PerceptionEvent. Feed content is treated strictly as DATA, never as
instructions — the cognition layer is responsible for refusing any
"ignore previous directives" payload that arrives in a feed body.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime

import feedparser
import httpx

from ..types import EventSource, PerceptionEvent, RiskSignal

log = logging.getLogger(__name__)


@dataclass
class FeedConfig:
    name: str
    url: str
    source: EventSource
    poll_interval_s: float = 900.0


class RssFeedAggregator:
    def __init__(
        self,
        feeds: list[FeedConfig],
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._feeds = feeds
        self._http = http_client or httpx.AsyncClient(timeout=30.0)
        self._seen: dict[str, set[str]] = {f.name: set() for f in feeds}

    async def stream(self) -> AsyncIterator[PerceptionEvent]:
        queue: asyncio.Queue[PerceptionEvent] = asyncio.Queue(maxsize=1000)

        async def poll_one(feed: FeedConfig) -> None:
            while True:
                try:
                    async for event in self._poll_feed(feed):
                        await queue.put(event)
                except Exception as exc:
                    log.warning("feed %s error: %s", feed.name, exc)
                await asyncio.sleep(feed.poll_interval_s)

        tasks = [asyncio.create_task(poll_one(f)) for f in self._feeds]
        try:
            while True:
                yield await queue.get()
        finally:
            for t in tasks:
                t.cancel()

    async def _poll_feed(self, feed: FeedConfig) -> AsyncIterator[PerceptionEvent]:
        response = await self._http.get(feed.url)
        response.raise_for_status()
        parsed = feedparser.parse(response.text)

        for entry in parsed.entries:
            eid = self._entry_id(entry)
            if eid in self._seen[feed.name]:
                continue
            self._seen[feed.name].add(eid)

            yield PerceptionEvent(
                source=feed.source,
                observed_at=datetime.now(UTC),
                identifier=eid,
                payload={
                    "feed": feed.name,
                    "title": entry.get("title", ""),
                    "link": entry.get("link", ""),
                    "summary": entry.get("summary", "")[:2000],
                    "published": entry.get("published", ""),
                },
                signals=(RiskSignal(f"intel:{feed.name}", 0.4, "external intel"),),
            )

    @staticmethod
    def _entry_id(entry: dict) -> str:
        if entry.get("id"):
            return str(entry["id"])
        if entry.get("link"):
            return str(entry["link"])
        body = (entry.get("title", "") + entry.get("summary", "")).encode()
        return hashlib.sha256(body).hexdigest()[:16]


DEFAULT_FEEDS = [
    FeedConfig(
        name="rekt-news",
        url="https://rekt.news/rss/feed.xml",
        source=EventSource.INTEL_REKT,
        poll_interval_s=1800,
    ),
    FeedConfig(
        name="cve-recent",
        url="https://cve.mitre.org/data/downloads/allitems.xml",
        source=EventSource.INTEL_CVE,
        poll_interval_s=3600,
    ),
]
