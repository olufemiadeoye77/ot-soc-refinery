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
