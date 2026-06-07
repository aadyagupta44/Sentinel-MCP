"""Bot tests — tick() generation and run() loop with a fake clock."""

from random import Random

from simulator.bots import AdversarialBot, NormalBot
from simulator.iocs import IocProvider
from simulator.profiles import PROFILES
from simulator.sink import InMemorySink

IOCS = IocProvider(c2_ips=("9.9.9.9",), malware_hashes=("deadbeef",))


class FakeClock:
    """Virtual clock for single-bot run() loops — sleep advances time instantly."""

    def __init__(self) -> None:
        self.t = 0.0

    def now(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        self.t += seconds


class TestNormalBot:
    async def test_tick_emits_a_login(self):
        sink = InMemorySink()
        bot = NormalBot(PROFILES, sink, Random(1))
        n = await bot.tick()
        assert n >= 1
        assert bot.logins_emitted == 1
        assert any(log["event_type"] == "auth" for log in sink.logs)

    async def test_run_emits_at_least_50_logins_over_5_minutes(self):
        sink = InMemorySink()
        bot = NormalBot(PROFILES, sink, Random(1))
        clock = FakeClock()
        await bot.run(
            duration_s=300, min_interval=2, max_interval=8, sleep=clock.sleep, clock=clock.now
        )
        assert bot.logins_emitted >= 50
        successful_logins = [
            log for log in sink.logs if log["event_type"] == "auth" and log["success"]
        ]
        assert len(successful_logins) >= 50


class TestAdversarialBot:
    async def test_tick_fires_named_scenario(self):
        sink = InMemorySink()
        bot = AdversarialBot(PROFILES, IOCS, sink, Random(0))
        name = await bot.tick("brute_force")
        assert name == "brute_force"
        assert len(sink.alerts) == 1
        assert any(log["event_type"] == "auth" for log in sink.logs)

    async def test_run_fires_at_least_one_scenario(self):
        sink = InMemorySink()
        bot = AdversarialBot(PROFILES, IOCS, sink, Random(2))
        clock = FakeClock()
        fired = await bot.run(
            duration_s=300, min_interval=300, max_interval=1200, sleep=clock.sleep, clock=clock.now
        )
        assert len(fired) >= 1
        assert len(sink.alerts) >= 1
        assert all(name in SCENARIO_SET for name in fired)


SCENARIO_SET = {
    "impossible_travel",
    "brute_force",
    "suspicious_process",
    "data_exfiltration",
    "known_bad_ip",
}
