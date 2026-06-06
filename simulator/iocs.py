"""IOC provider — real abuse.ch C2 IPs and malware hashes for adversarial bots.

In mock mode the abuse.ch adapter is pre-seeded with known test IOCs; in live
mode it downloads the real FeodoTracker / MalwareBazaar feeds. Either way the
adversarial scenarios fire with genuine indicators. Hard-coded fallbacks keep
the simulator working if the feeds are empty.
"""

from dataclasses import dataclass
from random import Random

_FALLBACK_C2_IPS = ("185.220.101.34", "91.108.56.181")
_FALLBACK_HASHES = ("44d88612fea8a8f36de82e1278abb02f",)


@dataclass(frozen=True)
class IocProvider:
    c2_ips: tuple[str, ...]
    malware_hashes: tuple[str, ...]

    @classmethod
    async def from_abuse_ch(cls) -> "IocProvider":
        from sentinel.adapters.abuse_ch import get_abuse_ch_adapter

        adapter = get_abuse_ch_adapter()
        ips = tuple(await adapter.known_c2_ips()) or _FALLBACK_C2_IPS
        hashes = tuple(await adapter.known_malware_hashes()) or _FALLBACK_HASHES
        return cls(c2_ips=ips, malware_hashes=hashes)

    def random_c2_ip(self, rng: Random) -> str:
        return rng.choice(self.c2_ips)

    def random_malware_hash(self, rng: Random) -> str:
        return rng.choice(self.malware_hashes)
