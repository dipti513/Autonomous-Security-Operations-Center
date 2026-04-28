from __future__ import annotations

import asyncio
from typing import Any

from .models import AgentMessage


class AgentStream:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    async def publish(self, message: AgentMessage) -> None:
        payload = message.to_dict()
        for queue in list(self._subscribers):
            await queue.put(payload)

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)

