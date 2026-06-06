"""Simulator entry point.

    python -m simulator.main --duration 300                 # write to OpenSearch
    python -m simulator.main --duration 60 --dry-run        # in-memory, no writes

Point it at a real OpenSearch with MOCK_ADAPTERS=false (and OPENSEARCH_URL set)
so the Sentinel tools can investigate the generated events.
"""

import argparse
import asyncio
import time
from random import Random
from typing import Any

import structlog

from simulator.bots import AdversarialBot, ClockFn, NormalBot, SleepFn
from simulator.iocs import IocProvider
from simulator.profiles import PROFILES
from simulator.sink import EventSink, InMemorySink, OpenSearchSink

logger = structlog.get_logger("simulator")


async def run_simulator(
    *,
    duration_s: float = 300.0,
    seed: int | None = None,
    sink: EventSink | None = None,
    iocs: IocProvider | None = None,
    rng: Random | None = None,
    sleep: SleepFn = asyncio.sleep,
    clock: ClockFn = time.monotonic,
    normal_interval: tuple[float, float] = (2.0, 8.0),
    adversarial_interval: tuple[float, float] = (300.0, 1200.0),
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run the normal + adversarial bots concurrently for `duration_s`."""
    rng = rng or Random(seed)
    if sink is None:
        sink = InMemorySink() if dry_run else OpenSearchSink()
    if iocs is None:
        iocs = await IocProvider.from_abuse_ch()

    normal = NormalBot(PROFILES, sink, Random(rng.random()))
    adversarial = AdversarialBot(PROFILES, iocs, sink, Random(rng.random()))

    logger.info("simulator_starting", duration_s=duration_s, profiles=len(PROFILES))
    await asyncio.gather(
        normal.run(
            duration_s=duration_s,
            min_interval=normal_interval[0],
            max_interval=normal_interval[1],
            sleep=sleep,
            clock=clock,
        ),
        adversarial.run(
            duration_s=duration_s,
            min_interval=adversarial_interval[0],
            max_interval=adversarial_interval[1],
            sleep=sleep,
            clock=clock,
        ),
    )
    logger.info(
        "simulator_finished",
        logins=normal.logins_emitted,
        scenarios_fired=adversarial.scenarios_fired,
    )
    return {"sink": sink, "normal": normal, "adversarial": adversarial}


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel SOC traffic simulator")
    parser.add_argument("--duration", type=float, default=300.0, help="Run time in seconds")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible runs")
    parser.add_argument("--dry-run", action="store_true", help="Use the in-memory sink (no writes)")
    parser.add_argument("--normal-min", type=float, default=2.0)
    parser.add_argument("--normal-max", type=float, default=8.0)
    parser.add_argument("--adv-min", type=float, default=300.0)
    parser.add_argument("--adv-max", type=float, default=1200.0)
    args = parser.parse_args()

    result = asyncio.run(
        run_simulator(
            duration_s=args.duration,
            seed=args.seed,
            dry_run=args.dry_run,
            normal_interval=(args.normal_min, args.normal_max),
            adversarial_interval=(args.adv_min, args.adv_max),
        )
    )
    normal = result["normal"]
    adversarial = result["adversarial"]
    print(  # noqa: T201 — CLI summary
        f"Simulator done: {normal.logins_emitted} logins emitted, "
        f"{len(adversarial.scenarios_fired)} adversarial scenario(s) fired "
        f"({', '.join(adversarial.scenarios_fired) or 'none'})."
    )


if __name__ == "__main__":
    main()
