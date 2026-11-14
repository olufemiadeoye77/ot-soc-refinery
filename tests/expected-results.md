
# wazuh-logtest regression cases

All commands assume:
- Docker container: `single-node-wazuh.manager-1`
- Wazuh version: `4.14.9`
- Decoder + rules deployed (see README §8)

Run each case with:

```bash
MSYS_NO_PATHCONV=1 docker exec -i single-node-wazuh.manager-1 \
  /var/ossec/bin/wazuh-logtest -v <<'EOF'
<log line>
EOF
```

---

## Case A — CRITICAL / current surge

**Input**

```
process_anomaly {"severity":"critical","reason":"current surge","src":"10.0.0.7"}
```

**Expected Phase 2**

```
name: 'ot_soc_ai_agent'
severity: 'critical'
reason: 'current surge'
src: '10.0.0.7'
```

**Expected Phase 3**

```
*Rule 100202 matched
*Rule 100204 matched

id: '100204'
level: '14'
description: 'OT SOC: pump current surge - possible unauthorized actuation'
```

**Expected alert** — generated, `mail: True`.

**MITRE warning**

```
** Wazuh-Logtest: WARNING: Mitre Technique ID 'T0839' not found in database.
```

Expected (see README §7). Does not affect rule firing.

---

## Case B — HIGH / setpoint drift

**Input**

```
process_anomaly {"severity":"high","reason":"setpoint drift","src":"10.0.0.5"}
```

**Expected Phase 2**

```
name: 'ot_soc_ai_agent'
severity: 'high'
reason: 'setpoint drift'
src: '10.0.0.5'
```

**Expected Phase 3**

```
*Rule 100201 matched
*Rule 100203 matched

id: '100203'
level: '12'
description: 'OT SOC: pump setpoint drift detected'
```

**Expected alert** — generated, `mail: True`.

---

## Case C — HIGH / unknown vibration (false-positive guard)

**Input**

```
process_anomaly {"severity":"high","reason":"unknown vibration","src":"10.0.0.9"}
```

**Expected Phase 2**

```
name: 'ot_soc_ai_agent'
severity: 'high'
reason: 'unknown vibration'
src: '10.0.0.9'
```

**Expected Phase 3**

```
*Rule 100201 matched
[100203 must NOT match]

id: '100201'
level: '10'
description: 'OT SOC: AI anomaly agent flagged HIGH severity process anomaly'
```

**Expected alert** — generated, `mail: False`.

**Why this case matters**

100203 requires `reason = setpoint drift` **exactly**. The input uses
`unknown vibration`, so 100203 must reject. The absence of
`*Rule 100203 matched` in the log is the assertion. Without this test,
a broadened regex could silently escalate unrelated anomalies.

---

## Summary

| Case | Rules expected | Alert |
|------|---------------|-------|
| A | 100202 + 100204 (level 14) | yes, mail=True |
| B | 100201 + 100203 (level 12) | yes, mail=True |
| C | 100201 only (level 10) | yes, mail=False |

All three pass on `wazuh-logtest v4.14.9` (2026-11-14).