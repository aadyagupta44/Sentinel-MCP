"""Sentinel SOC traffic simulator.

A standalone synthetic-event generator for demos and testing. Normal bots emit
realistic login / file-access / process events; adversarial bots periodically
fire one of five attack scenarios using real abuse.ch C2 IPs and malware hashes.
Events are written to OpenSearch (or any EventSink) so the Sentinel tools
(search_logs, correlate_alerts, …) can investigate them.

Run:  python -m simulator.main --duration 300
"""

__all__ = ["__version__"]
__version__ = "1.0.0"
