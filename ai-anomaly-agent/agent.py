"""AI anomaly agent for OT DMZ.

Reads Zeek conn.log (Modbus connections), extracts features, and applies
an Isolation Forest model to flag anomalous behavior. Produces alerts to
stdout for now; Wazuh integration comes next session.

This is a sketch. The real model is trained on baseline traffic
from the refinery simulator during normal operation.
"""

import json
import sys
import time
from pathlib import Path
from collections import defaultdict


class ModbusAnomalyDetector:
    def __init__(self):
        # Baseline features seen during normal operation. The trained
        # model goes here next session. For the sketch, we use simple
        # statistical thresholds learned from the first 100 connections.
        self.write_counts_by_ip = defaultdict(int)
        self.read_counts_by_ip = defaultdict(int)
        self.warmup_connections = 100
        self.connection_count = 0

    def observe(self, record: dict) -> dict | None:
        """Process one Zeek connection. Return alert dict or None."""
        self.connection_count += 1

        src = record.get("id.orig_h", "unknown")
        func = record.get("modbus_function", "unknown")
        is_write = func in ("write_single_register", "write_multiple_registers")
        is_read = func in ("read_holding_registers", "read_input_registers")

        if is_write:
            self.write_counts_by_ip[src] += 1
        elif is_read:
            self.read_counts_by_ip[src] += 1

        # Warmup phase: learn the baseline, don't alert
        if self.connection_count <= self.warmup_connections:
            return None

        # Simple heuristic: a source IP that has never written before,
        # suddenly writing, is suspicious
        if is_write and self.write_counts_by_ip[src] == 1:
            return {
                "type": "behavioral_anomaly",
                "src_ip": src,
                "reason": f"first-ever Modbus write from {src}",
                "function": func,
                "severity": "high",
            }

        # A burst of writes (>10 in this run) from a single IP
        if is_write and self.write_counts_by_ip[src] > 10:
            return {
                "type": "behavioral_anomaly",
                "src_ip": src,
                "reason": f"write burst: {self.write_counts_by_ip[src]} writes from {src}",
                "function": func,
                "severity": "critical",
            }

        return None


def tail_log(path: Path):
    """Naive tail -f. Yields new lines as they're appended."""
    with path.open("r") as f:
        f.seek(0, 2)  # go to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


def main() -> int:
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/var/ot/telemetry/zeek/conn.log")
    if not log_path.exists():
        print(f"sketch mode: {log_path} not found, generating synthetic events", file=sys.stderr)
        _run_sketch_mode()
        return 0

    detector = ModbusAnomalyDetector()
    print(f"watching {log_path}...", file=sys.stderr)

    for line in tail_log(log_path):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        alert = detector.observe(record)
        if alert:
            print(json.dumps(alert))


def _run_sketch_mode() -> None:
    """Simulate 150 connections: 140 normal reads, 10 anomalous writes."""
    detector = ModbusAnomalyDetector()
    normal_ip = "10.0.1.10"
    attacker_ip = "10.0.4.66"

    print("=== Normal operation (140 reads from PLC) ===", file=sys.stderr)
    for _ in range(140):
        detector.observe({"id.orig_h": normal_ip, "modbus_function": "read_input_registers"})

    print("=== Attacker scanning (reads, no alerts expected) ===", file=sys.stderr)
    for _ in range(5):
        detector.observe({"id.orig_h": attacker_ip, "modbus_function": "read_holding_registers"})

    print("=== Attacker writing (expect alerts) ===", file=sys.stderr)
    for i in range(12):
        alert = detector.observe({"id.orig_h": attacker_ip, "modbus_function": "write_single_register"})
        if alert:
            print(json.dumps(alert))


if __name__ == "__main__":
    sys.exit(main())
