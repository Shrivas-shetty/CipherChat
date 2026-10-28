from app.services.baseline_store import BaselineStore


def test_store_ttl_consumption_and_item_eviction(monkeypatch):
    now = [10.0]
    store = BaselineStore()
    monkeypatch.setattr(store, "_clock", lambda: now[0])
    first, first_for_session = store.add("s1", 2, "text", {"text": "one"}, 3, 60, 2, 10)
    assert first_for_session
    assert not store.add("s1", 2, "text", {"text": "two"}, 3, 60, 2, 10)[1]
    third, _ = store.add("s2", 2, "text", {"text": "three"}, 3, 60, 2, 10)
    assert store.get(first, 60) is None
    assert store.consume(third, 60) is not None
    assert store.consume(third, 60) is None
    now[0] += 61
    assert store.get(first + 1, 60) is None


def test_store_byte_cap_evicts_oldest():
    store = BaselineStore()
    first, _ = store.add("a", 1, "image", {}, 7, 60, 5, 10)
    second, _ = store.add("b", 1, "image", {}, 7, 60, 5, 10)
    assert store.get(first, 60) is None and store.get(second, 60) is not None
