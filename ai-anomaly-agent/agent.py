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
import os
from pymodbus.client import ModbusTcpClient

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

def _run_live_poll(host: str, port: int) -> None:
    """Poll the simulator's Modbus registers, learn a baseline, flag deviations."""
    import statistics

    client = ModbusTcpClient(host, port=port)
    if not client.connect():
        print(f"ERROR: cannot connect to {host}:{port}", file=sys.stderr)
        sys.exit(1)

    print(f"polling {host}:{port} for baseline...", file=sys.stderr)

    baseline = {"pump1_setpoint": [], "pump1_current": [], "tank_level": []}
    warmup_ticks = 30
    tick = 0

    while True:
        try:
            hrs = client.read_holding_registers(1, 4, slave=0)
            irs = client.read_input_registers(1, 5, slave=0)
        except Exception as e:
            print(f"poll error: {e}", file=sys.stderr)
            time.sleep(1.0)
            continue

        if hrs.isError() or irs.isError():
            print(f"HR error: {hrs}  IR error: {irs}", file=sys.stderr)
            time.sleep(1.0)
            continue

        # HR[1] = pump1 setpoint (per working test client)
        # IR[1] = pump1 current (x10), IR[3] = tank level
        pump1_setpoint = hrs.registers[0]
        pump1_current = irs.registers[1] / 10.0
        tank_level = irs.registers[0]

        if tick < warmup_ticks:
            baseline["pump1_setpoint"].append(pump1_setpoint)
            baseline["pump1_current"].append(pump1_current)
            baseline["tank_level"].append(tank_level)
            tick += 1
            if tick == warmup_ticks:
                for k, vals in baseline.items():
                    print(f"baseline {k}: mean={statistics.mean(vals):.2f} "
                          f"stdev={statistics.pstdev(vals):.2f}", file=sys.stderr)
            time.sleep(1.0)
            continue

        sp_mean = statistics.mean(baseline["pump1_setpoint"])
        cur_mean = statistics.mean(baseline["pump1_current"])
        cur_std = statistics.pstdev(baseline["pump1_current"]) or 0.1

        if abs(pump1_setpoint - sp_mean) > 20:
            print(json.dumps({
                "type": "process_anomaly",
                "src": f"{host}:{port}",
                "reason": f"pump1 setpoint drift: {sp_mean:.0f}% -> {pump1_setpoint}%",
                "severity": "high",
                "tick": tick,
            }))

        if pump1_current > cur_mean + 3 * cur_std:
            print(json.dumps({
                "type": "process_anomaly",
                "src": f"{host}:{port}",
                "reason": f"pump1 current surge: {cur_mean:.1f} A -> {pump1_current:.1f} A",
                "severity": "critical",
                "tick": tick,
            }))

        tick += 1
        time.sleep(1.0)




def main() -> int:
    modbus_host = os.environ.get("MODBUS_HOST")
    if modbus_host:
        port = int(os.environ.get("MODBUS_PORT", "5020"))
        _run_live_poll(modbus_host, port)
        return 0

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
