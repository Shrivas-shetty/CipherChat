from app.bench.runner import schedule


def test_schedule_alternates_mode_order_by_repeat_parity():
    assert schedule(4) == [
        ("secure", "plain"),
        ("plain", "secure"),
        ("secure", "plain"),
        ("plain", "secure"),
    ]
