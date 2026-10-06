"""Live progress: what the agent is doing right now, streamed to the console.

Each request from the console names a progress channel (X-Progress-Channel).
While the request runs, the orchestrator, the tool registry and the execution
provider publish short events to that channel - "checking VM status", "job
Running", "verifying". The console subscribes with Server-Sent Events and shows
them as they happen instead of after the request returns.

Events carry only what the engineer already sees in the console: tool names,
statuses and summaries. Nothing here is read back by the agent.
"""

from __future__ import annotations

import asyncio
import contextvars
import re
import time
from collections.abc import AsyncIterator
from typing import Any

_channel: contextvars.ContextVar[str | None] = contextvars.ContextVar("progress_channel", default=None)

# A finished channel is kept briefly so a late subscriber still sees it.
CHANNEL_TTL_SECONDS = 600
STREAM_MAX_SECONDS = 900
KEEPALIVE_SECONDS = 15


class ProgressBus:
    def __init__(self) -> None:
        self._channels: dict[str, dict[str, Any]] = {}

    def _get(self, channel: str) -> dict[str, Any]:
        ch = self._channels.get(channel)
        if ch is None:
            ch = {"events": [], "updated": time.monotonic(), "waiters": set()}
            self._channels[channel] = ch
        return ch

    def publish(self, channel: str, event: dict[str, Any]) -> None:
        ch = self._get(channel)
        ch["events"].append({"seq": len(ch["events"]), "ts": time.time(), **event})
        ch["updated"] = time.monotonic()
        for waiter in list(ch["waiters"]):
            if not waiter.done():
                waiter.set_result(None)
        self._prune()

    async def stream(self, channel: str) -> AsyncIterator[dict[str, Any]]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + STREAM_MAX_SECONDS
        index = 0
        while loop.time() < deadline:
            ch = self._get(channel)
            while index < len(ch["events"]):
                event = ch["events"][index]
                index += 1
                yield event
                if event.get("kind") == "done":
                    return
            waiter = loop.create_future()
            ch["waiters"].add(waiter)
            try:
                await asyncio.wait_for(waiter, timeout=KEEPALIVE_SECONDS)
            except TimeoutError:
                yield {"kind": "keepalive"}
            finally:
                ch["waiters"].discard(waiter)

    def _prune(self) -> None:
        cutoff = time.monotonic() - CHANNEL_TTL_SECONDS
        for name in [n for n, ch in self._channels.items() if ch["updated"] < cutoff and not ch["waiters"]]:
            self._channels.pop(name, None)


BUS = ProgressBus()


def bind(channel: str | None) -> contextvars.Token:
    """Route events from this request (and tasks it spawns) to `channel`."""
    return _channel.set(channel)


def unbind(token: contextvars.Token) -> None:
    _channel.reset(token)


def emit(kind: str, text: str, status: str = "running", **extra: Any) -> None:
    """Publish one event to the current request's channel, if it has one."""
    channel = _channel.get()
    if channel:
        BUS.publish(channel, {"kind": kind, "text": text, "status": status, **extra})


_CHANNEL_PATTERN = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class ProgressMiddleware:
    """Pure ASGI middleware (same task as the endpoint, so the context variable
    reaches every await inside it): binds the request's X-Progress-Channel and
    publishes a final 'done' event when the request ends."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        raw = dict(scope.get("headers") or []).get(b"x-progress-channel", b"").decode("latin-1")
        if not _CHANNEL_PATTERN.match(raw):
            await self.app(scope, receive, send)
            return
        token = bind(raw)
        try:
            await self.app(scope, receive, send)
        finally:
            emit("done", "Finished", "healthy")
            unbind(token)


def valid_channel(channel: str) -> bool:
    return bool(_CHANNEL_PATTERN.match(channel))
