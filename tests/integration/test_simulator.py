"""Phase 6 integration — the simulator end to end and its incidents correlating.

Runs the orchestrator with the in-memory sink (real asyncio, tiny intervals) and
feeds generated adversarial alerts through the live correlate_alerts logic.
"""

import json
from datetime import UTC, datetime
from random import Random
from unittest.mock import AsyncMock

from simulator.iocs import IocProvider
from simulator.main import run_simulator
from simulator.profiles import PROFILES
from simulator.scenarios import impossible_travel, known_bad_ip

IOCS = IocProvider(c2_ips=("9.9.9.9",), malware_hashes=("deadbeef",))


class TestRunSimulator:
    async def test_dry_run_produces_normal_and_adversarial_traffic(self):
        result = await run_simulator(
            duration_s=0.5,
            dry_run=True,
            iocs=IOCS,
            seed=0,
            normal_interval=(0.01, 0.02),
            adversarial_interval=(0.01, 0.03),
        )
        sink = result["sink"]
        # Normal login traffic flowed
        assert any(log["event_type"] == "auth" for log in sink.logs)
        # At least one adversarial scenario fired (alert emitted)
        assert len(sink.alerts) >= 1
        # Adversarial events carry the real C2 IP → search_logs("9.9.9.9") would hit
        assert any("9.9.9.9" in json.dumps(log) for log in sink.logs)

    async def test_defaults_construct_opensearch_sink_and_abuse_ch_iocs(self):
        # No sink/iocs passed → OpenSearchSink (mock adapter) + IocProvider.from_abuse_ch().
        from simulator.sink import OpenSearchSink

        result = await run_simulator(
            duration_s=0.2,
            seed=1,
            normal_interval=(0.01, 0.02),
            adversarial_interval=(0.01, 0.02),
        )
        assert isinstance(result["sink"], OpenSearchSink)
        assert result["normal"].logins_emitted >= 1
        assert len(result["adversarial"].scenarios_fired) >= 1

    def test_main_cli_dry_run(self, monkeypatch, capsys):
        import sys

        from simulator import main as sim_main

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "simulator",
                "--dry-run",
                "--duration",
                "0.2",
                "--seed",
                "3",
                "--normal-min",
                "0.01",
                "--normal-max",
                "0.02",
                "--adv-min",
                "0.01",
                "--adv-max",
                "0.02",
            ],
        )
        sim_main.main()
        assert "Simulator done" in capsys.readouterr().out


class TestSimulatedIncidentsCorrelate:
    async def test_same_user_scenarios_form_one_cluster(self, monkeypatch):
        now = datetime.now(UTC)
        profile = PROFILES[0]
        rng = Random(0)
        _, alert_a = impossible_travel(profile, IOCS, rng, now)
        _, alert_b = known_bad_ip(profile, IOCS, rng, now)

        from sentinel.adapters.opensearch import get_opensearch_adapter
        from sentinel.tools import alerts as alert_tools

        # Feed the simulator's alerts to the live correlate_alerts logic.
        monkeypatch.setattr(
            get_opensearch_adapter(), "get_alerts", AsyncMock(return_value=[alert_a, alert_b])
        )
        result = await alert_tools._execute_correlate_alerts({})

        assert result["total_alerts"] == 2
        assert result["correlated_cluster_count"] >= 1
        biggest = max(result["clusters"], key=lambda c: c["alert_count"])
        assert biggest["alert_count"] == 2
        # They share the same user (and the same C2 source IP)
        assert "user" in biggest["shared_factors"]
