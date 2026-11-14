# OT SOC Detection Verification Report

**Date:** 2026-11-14
**Environment:** Wazuh 4.14.9 single-node Docker, container `single-node-wazuh.manager-1`
**Rules loaded:** 8,455
**Test harness:** `wazuh-logtest -v`

---

## 1. Executive summary

Three detection test cases were run against the OT SOC AI anomaly
decoder and rules. **All three pass.** Severity, reason, and src are
extracted correctly; parent and child rules fire as designed; the
false-positive guard (Case C) confirms that an unrecognised reason does
**not** escalate to a MITRE-mapped child rule.

One cosmetic limitation was identified: Wazuh 4.14 ships Enterprise-only
MITRE content, so T0839 (ICS) cannot resolve. Alerts still fire. Details
in §5.

---

## 2. Architecture

```
┌───────────────────────┐
│  AI anomaly agent     │
│  (upstream producer)  │
└───────────┬───────────┘
            │  process_anomaly {"severity":..., "reason":..., "src":...}
            ▼
┌───────────────────────┐
│  wazuh-logcollector   │
└───────────┬───────────┘
            ▼
┌───────────────────────┐     ┌─────────────────────────────┐
│  wazuh-analysisd      │────▶│  Decoder: ot_soc_ai_agent   │
│                       │     │  Extracts: severity,reason, │
│                       │     │            src              │
│                       │     └─────────────┬───────────────┘
│                       │                   ▼
│                       │     ┌─────────────────────────────┐
│                       │────▶│  Rules 100201-100204        │
│                       │     │  Parent: severity           │
│                       │     │  Child:  reason             │
│                       │     └─────────────┬───────────────┘
└───────────┬───────────┘                   ▼
            │                    ┌──────────────────────┐
            │                    │  wazuh-indexer       │
            │                    └──────────┬───────────┘
            ▼                               ▼
┌───────────────────────┐        ┌──────────────────────┐
│  ossec.log            │        │  Wazuh Dashboard     │
│  (parse/rule errors)  │        │  (alerts, MITRE)     │
└───────────────────────┘        └──────────────────────┘
```

---

## 3. Decoder flow (correct pattern)

```
                 Log line
                    │
                    ▼
   ┌────────────────────────────────┐
   │ prematch: process_anomaly      │  ← must be present
   └───────────────┬────────────────┘
                   ▼
   ┌────────────────────────────────────────────────────┐
   │ regex (PCRE2, 3 capture groups, fixed order):      │
   │   "severity":"([^"]+)".*"reason":"([^"]+)".*"src" │
   └───────────────┬────────────────────────────────────┘
                   ▼
   ┌────────────────────────────────┐
   │ order: severity, reason, src   │  ← count = 3 = captures
   └───────────────┬────────────────┘
                   ▼
   ┌────────────────────────────────┐
   │ Fields emitted → rules engine  │
   └────────────────────────────────┘
```

---

## 4. Rule tree

```
Rule 1 (Generic syslog parent, built-in)
 ├── 100201  severity=high        → level 10
 │     └── 100203  reason=setpoint drift  → level 12 · T0839
 └── 100202  severity=critical    → level 14
       └── 100204  reason=current surge   → level 14 · T0839
```

---

## 5. MITRE limitation — evidence

```
$ docker exec single-node-wazuh.manager-1 \
    python3 -c "import sqlite3; c=sqlite3.connect('/var/ossec/var/db/mitre.db'); \
    print('total:', c.execute('SELECT COUNT(*) FROM technique').fetchone()[0]); \
    print('T08xx:', c.execute(\"SELECT COUNT(*) FROM technique WHERE id LIKE 'T08%'\").fetchone()[0]); \
    print('T0839:', c.execute(\"SELECT * FROM technique WHERE id='T0839'\").fetchall())"

total: 750
T08xx: 0
T0839: []
```

| Metric | Value |
|--------|-------|
| `mitre.db` size | 14.7 MB |
| `db_version` | 1 |
| `mitre_version` | 2.0 (Enterprise ATT&CK) |
| Techniques | 750 |
| ICS techniques (T08xx) | **0** |
| T0839 present | **No** |

**Conclusion:** Wazuh 4.14's bundled MITRE content is Enterprise-only.
T0839 is an ICS technique and cannot resolve from the default DB.

**Impact:** the `wazuh-logtest` warning is cosmetic. Alerts fire
correctly. The `mitre.id` field is absent from the indexed document.

**Mitigation options** (production):

1. Ingest ICS ATT&CK content into `/var/ossec/var/db/mitre.db`
2. Use a Wazuh content bundle that includes ICS
3. Manually insert T0839 into the `technique` table (script below)

```python
# Example — insert T0839 into mitre.db (run inside the container)
import sqlite3
c = sqlite3.connect('/var/ossec/var/db/mitre.db')
c.execute('''
    INSERT OR IGNORE INTO technique
      (id, name, description, mitre_version, mitre_detection)
    VALUES (?, ?, ?, ?, ?)
''', (
    'T0839',
    'Pump/Valve Manipulation',
    'Adversaries may manipulate pump or valve setpoints to cause '
    'physical process impact.',
    '2.0',
    'Monitor ICS setpoint writes and process-variable deviations.'
))
c.commit()
```

> ⚠️ Not recommended for production: content updates overwrite
> `mitre.db`, so the insert must be re-applied after every update.

---

## 6. Test results

### Case A — CRITICAL / current surge ✅

| Check | Result |
|-------|--------|
| severity decoded | ✅ `critical` |
| reason decoded | ✅ `current surge` |
| src decoded | ✅ `10.0.0.7` |
| Rule 100202 fired | ✅ level 14 |
| Rule 100204 fired | ✅ level 14 |
| Alert generated | ✅ `mail: True` |

### Case B — HIGH / setpoint drift ✅

| Check | Result |
|-------|--------|
| severity decoded | ✅ `high` |
| reason decoded | ✅ `setpoint drift` |
| src decoded | ✅ `10.0.0.5` |
| Rule 100201 fired | ✅ level 10 |
| Rule 100203 fired | ✅ level 12 |
| Alert generated | ✅ `mail: True` |

### Case C — HIGH / unknown vibration ✅ (false-positive guard)

| Check | Result |
|-------|--------|
| severity decoded | ✅ `high` |
| reason decoded | ✅ `unknown vibration` |
| src decoded | ✅ `10.0.0.9` |
| Rule 100201 fired | ✅ level 10 |
| Rule 100203 did NOT fire | ✅ as designed |
| Alert generated | ✅ `mail: False` |

---

## 7. Timeline of decoder experiments

| Attempt | Pattern | Fields decoded | Rules fired | Outcome |
|---------|---------|---------------|-------------|---------|
| 1 | 3 sibling children | severity only | 100202 only | ❌ reason/src dropped |
| 2 | 3 chained `<regex>` in one child | **none** | none | ❌ `<order>` count mismatch → silent reject |
| 3 | `<order>json</order>` | `json` literal field only | none | ❌ custom decoder does not invoke JSON parser |
| 4 | **1 regex, 3 captures, ordered `<order>`** | **severity, reason, src** | **100202 + 100204** | ✅ correct |

---

## 8. Lessons learned

1. **"Decoder matched" ≠ "fields decoded."** Always inspect Phase 2.
2. **Multiple `<regex>` in one decoder are alternatives, not sequential
   passes.** `<order>` count must equal the winning regex's capture-group
   count.
3. **Sibling child decoders run once; first match wins.**
4. **Wazuh silently drops malformed decoders.** Tail
   `/var/ossec/logs/ossec.log` after every change.
5. **Wazuh ships Enterprise-only MITRE content.** ICS techniques do not
   resolve without custom content.
6. **Test the negative case.** Case C proves the pipeline does not
   over-fire. It is the most important of the three.