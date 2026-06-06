"""Normal and adversarial traffic bots.

Each bot exposes `tick()` (emit one batch of events — synchronous to test) and
`run()` (loop tick + sleep until a duration elapses). `run()` takes injectable
`sleep`/`clock` so tests can drive it without real time.
"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from random import Random

import structlog

from simulator.events import file_access_event, login_event, process_event
from simulator.iocs import IocProvider
from simulator.profiles import Profile
from simulator.scenarios import SCENARIO_NAMES, SCENARIOS
from simulator.sink import EventSink

logger = structlog.get_logger("simulator.bots")

SleepFn = Callable[[float], Awaitable[None]]
ClockFn = Callable[[], float]


def _now() -> datetime:
    return datetime.now(UTC)


class NormalBot:
    """Emits routine login / file-access / process events for random employees."""

    def __init__(self, profiles: tuple[Profile, ...], sink: EventSink, rng: Random) -> None:
        self._profiles = profiles
        self._sink = sink
        self._rng = rng
        self.logins_emitted = 0

    async def tick(self) -> int:
        profile = self._rng.choice(self._profiles)
        now = _now()
        await self._sink.write_log(login_event(profile, self._rng, now))
        self.logins_emitted += 1
        count = 1
        roll = self._rng.random()
        if roll < 0.5:
            await self._sink.write_log(file_access_event(profile, self._rng, now))
            count += 1
        elif roll < 0.8:
            await self._sink.write_log(process_event(profile, self._rng, now))
            count += 1
        return count

    async def run(
        self,
        *,
        duration_s: float,
        min_interval: float = 2.0,
        max_interval: float = 8.0,
        sleep: SleepFn = asyncio.sleep,
        clock: ClockFn = time.monotonic,
    ) -> int:
        start = clock()
        total = 0
        while clock() - start < duration_s:
            total += await self.tick()
            await sleep(self._rng.uniform(min_interval, max_interval))
        return total


class AdversarialBot:
    """Periodically fires one of the five attack scenarios."""

    def __init__(
        self,
        profiles: tuple[Profile, ...],
        iocs: IocProvider,
        sink: EventSink,
        rng: Random,
    ) -> None:
        self._profiles = profiles
        self._iocs = iocs
        self._sink = sink
        self._rng = rng
        self.scenarios_fired: list[str] = []

    async def tick(self, scenario_name: str | None = None) -> str:
        name = scenario_name or self._rng.choice(SCENARIO_NAMES)
        profile = self._rng.choice(self._profiles)
        logs, alert = SCENARIOS[name](profile, self._iocs, self._rng, _now())
        for doc in logs:
            await self._sink.write_log(doc)
        await self._sink.write_alert(alert)
        self.scenarios_fired.append(name)
        logger.info("adversarial_scenario_fired", scenario=name, user=profile.email)
        return name

    async def run(
        self,
        *,
        duration_s: float,
        min_interval: float = 300.0,
        max_interval: float = 1200.0,
        sleep: SleepFn = asyncio.sleep,
        clock: ClockFn = time.monotonic,
    ) -> list[str]:
        start = clock()
        # Fire once promptly so a short run still produces an incident.
        if clock() - start < duration_s:
            await self.tick()
            await sleep(self._rng.uniform(min_interval, max_interval))
        while clock() - start < duration_s:
            await self.tick()
            await sleep(self._rng.uniform(min_interval, max_interval))
        return self.scenarios_fired
