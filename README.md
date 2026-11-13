# OT SOC for Refinery Process Simulation

Sketch phase. A miniature OT Security Operations Center targeting a
refinery pump station, with two industrial AI agents:
- behavioral anomaly detection at the OT DMZ
- context-aware alert triage in the SOC

## Status

This is the architecture sketch. Dockerfiles, Suricata rules, Wazuh
rules, and full AI implementation come in later sessions.

## Repo layout

    refinery-simulator/   Modbus pump station (python sketch, runs locally)
    ai-anomaly-agent/     Behavioral anomaly detector (python sketch, runs locally)
    ai-triage-agent/      Alert triage with local LLM (not started)
    suricata/rules/       ICS Modbus rules (not started)
    wazuh/rules/          Correlation rules (not started)
    docker-compose.yml    Full stack wiring (sketch, not runnable yet)

## What runs today

    cd refinery-simulator && python simulator.py
    cd ai-anomaly-agent && python agent.py

Both are standalone Python sketches. No Docker required to verify the logic.

## What is next

1. Dockerfiles for refinery-simulator and ai-anomaly-agent
2. Suricata rules for Modbus function codes
3. Wazuh rule file for correlating alerts
4. Real Isolation Forest training on baseline traffic
5. Triage agent with Ollama

## Standards and frameworks

- IEC 62443 zones and conduits (network segmentation above)
- Purdue model (OT zone = Level 1/2, DMZ = 3.5, SOC = 4/5)
- MITRE ATT&CK for ICS (attack scenarios in later sessions)
## Phase 2a - Simulator containerized

The refinery Modbus simulator is containerized and verified end-to-end.

Run:
    docker compose build refinery-simulator
    docker compose up -d refinery-simulator

Test:
    python scripts/test-modbus-client.py 127.0.0.1 5020

Expected: pump1 setpoint 40% -> write HR 40001=100 -> pump1 current rises ~4.5 A to ~11.9 A.

Notes:
- pymodbus pinned to ==3.5.4 in both requirements files
- Simulator listens on 0.0.0.0:5020, published to host on 127.0.0.1:5020
- Known cosmetic: tank level drains to 0% because outflow > inflow at 40% pump speed
## Phase 2b - AI anomaly agent containerized

The ai-anomaly-agent is built and verified in sketch mode (synthetic events).

Build:
    docker compose build ai-anomaly-agent

Run:
    docker run --rm ot-soc-refinery-ai-anomaly-agent

Expected: three JSON alerts - first-ever write (high), write burst x11 (critical),
write burst x12 (critical). 140 normal reads and 5 attacker reads produce no alerts.

Notes:
- Agent currently reads Zeek conn.log JSON lines (Phase B wires real Zeek traffic)
- Falls back to sketch mode when the log is absent
- scikit-learn and numpy are pinned in requirements but not yet used by agent.py;
  Isolation Forest training lands in Phase A2
- First build is slow (~10-12 min) because scikit-learn/numpy compile from source
## Phase 2c - Live Modbus polling

The ai-anomaly-agent now polls the refinery simulator directly over Modbus/TCP.
It learns a 30-tick baseline (setpoint, pump current, tank level), then flags:
- setpoint drift > 20% from baseline mean (high)
- pump1 current > baseline mean + 3 sigma (critical)

Run:
    docker compose up -d refinery-simulator
    docker compose up ai-anomaly-agent

Trigger (in a second terminal):
    python scripts/test-modbus-client.py 127.0.0.1 5020

Observed alerts:
    pump1 setpoint drift: 40% -> 100%   (high)
    pump1 current surge: 4.8 A -> 12.0 A  (critical)

Known limitation: alerts fire every tick while the anomaly persists.
Follow-up: transition-only alerting (edge detection).
## Phase 2d - OT DMZ sensor stack (Suricata + Zeek)

Two network sensors run on the ot_zone bridge alongside the refinery simulator.

Suricata:
- Custom Modbus rules in suricata/rules/modbus.rules (FC6 write, FC16 write, pump1 setpoint write)
- Validated at startup: "3 rules successfully loaded, 3 signatures processed, 3 inspect application layer"
- eve.json output mounted at telemetry/suricata/

Zeek:
- Base Modbus parser active, BPF filter "ip or not ip" initialized
- Logs configured to telemetry/zeek/ (container path /usr/local/zeek/logs/current)

Known limitation on Docker Desktop for Windows:
- Container-to-container unicast traffic is not exposed to a sniffing container on the bridge
- netshoot capture on ot_zone returned "0 packets captured" while Modbus traffic was flowing
- On a Linux Docker host, Suricata and Zeek on the same bridge capture this traffic live
- The AI anomaly agent (phase 2c) provides real-time detection in both environments

Proof artifacts:
- Suricata rule load: docker compose logs suricata | grep "rules successfully loaded"
- Zeek BPF: docker exec ot-soc-refinery-zeek-1 cat /usr/local/zeek/logs/packet_filter.log
