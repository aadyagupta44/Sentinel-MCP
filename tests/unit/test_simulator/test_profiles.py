"""Employee profile tests."""

from collections import Counter

from simulator.profiles import DEPARTMENTS, PROFILES


def test_ten_profiles():
    assert len(PROFILES) == 10


def test_five_departments_two_each():
    counts = Counter(p.department for p in PROFILES)
    assert set(counts) == set(DEPARTMENTS)
    assert all(c == 2 for c in counts.values())


def test_emails_and_hostnames_unique():
    assert len({p.email for p in PROFILES}) == 10
    assert len({p.hostname for p in PROFILES}) == 10
