from collections import defaultdict, deque
from threading import Lock
from time import monotonic

_lock = Lock()
_events = defaultdict(deque)


def sliding_window_limit(key, *, limit: int, window_seconds: int = 60) -> int | None:
    now = monotonic()
    cutoff = now - window_seconds
    with _lock:
        queue = _events[key]
        while queue and queue[0] <= cutoff:
            queue.popleft()
        if len(queue) >= limit:
            return max(1, int(window_seconds - (now - queue[0])))
        queue.append(now)
    return None
