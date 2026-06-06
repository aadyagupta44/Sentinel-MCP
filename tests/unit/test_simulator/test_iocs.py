"""IOC provider tests."""

from random import Random

from simulator.iocs import IocProvider


async def test_from_abuse_ch_uses_seeded_feeds():
    # abuse.ch adapter is seeded in mock mode (the suite default).
    provider = await IocProvider.from_abuse_ch()
    assert "185.220.101.34" in provider.c2_ips
    assert "44d88612fea8a8f36de82e1278abb02f" in provider.malware_hashes


def test_random_pickers_return_known_values():
    provider = IocProvider(c2_ips=("1.1.1.1", "2.2.2.2"), malware_hashes=("h1",))
    assert provider.random_c2_ip(Random(0)) in provider.c2_ips
    assert provider.random_malware_hash(Random(0)) == "h1"
