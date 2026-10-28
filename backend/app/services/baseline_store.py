"""Bounded, process-local storage for the explicitly enabled plaintext comparison."""
from collections import OrderedDict
from dataclasses import dataclass
import threading
import time


@dataclass
class Item:
    id: int
    session_id: str
    recipient_id: int
    kind: str
    created: float
    value: dict
    size: int


class BaselineStore:
    def __init__(self):
        self._items: OrderedDict[int, Item] = OrderedDict()
        self._next_id = 1
        self._audited_sessions: set[str] = set()
        self._lock = threading.RLock()
        self._clock = time.monotonic

    def _expire(self, now: float, ttl: float):
        for key, item in list(self._items.items()):
            if now - item.created >= ttl:
                self._items.pop(key, None)

    def add(self, session_id: str, recipient_id: int, kind: str, value: dict, size: int,
            ttl: float, max_items: int, max_bytes: int) -> tuple[int, bool]:
        now = self._clock()
        with self._lock:
            self._expire(now, ttl)
            item_id = self._next_id
            self._next_id += 1
            first = session_id not in self._audited_sessions
            self._audited_sessions.add(session_id)
            self._items[item_id] = Item(item_id, session_id, recipient_id, kind, now, value, size)
            while self._items and (len(self._items) > max_items or sum(x.size for x in self._items.values()) > max_bytes):
                self._items.popitem(last=False)
            return item_id, first

    def get(self, item_id: int, ttl: float) -> Item | None:
        with self._lock:
            self._expire(self._clock(), ttl)
            return self._items.get(item_id)

    def consume(self, item_id: int, ttl: float) -> Item | None:
        with self._lock:
            self._expire(self._clock(), ttl)
            return self._items.pop(item_id, None)


store = BaselineStore()
