from app.bench.payloads import make_rgb, make_text


def test_payloads_have_exact_lengths_and_are_deterministic():
    assert len(make_text(2000)) == 2000
    assert make_text(100, seed=99) == make_text(100, seed=99)
    assert make_text(40, marker="SECRETWORD123", seed=2).startswith("SECRETWORD123 ")
    assert len(make_rgb(12)) == 12 * 12 * 3
    assert make_rgb(12, seed=7) == make_rgb(12, seed=7)
