from secwatch.geo import Geo


def test_local_vs_public_without_databases():
    geo = Geo("", "")
    assert geo.lookup("10.1.2.3")["country"] == "локальная сеть"
    assert geo.lookup("172.20.0.5")["country"] == "локальная сеть"
    assert geo.lookup("127.0.0.1")["country"] == "локальная сеть"
    assert geo.lookup("203.0.113.5")["country"] == "—"  # public (documentation) range, no DB
    assert geo.lookup("not-an-ip") == {"country": "—", "asn": "—"}
    assert not geo.available
