"""Refinery pump station Modbus simulator.

Models a solvent-extraction pump station with two pumps, one tank, and
one outlet valve. Exposes Modbus/TCP registers that an OpenPLC instance
or an attacker can read and write.

Register map:
  Holding Registers (read/write):
    40001 - Pump 1 speed setpoint (0-100 %)
    40002 - Pump 2 speed setpoint (0-100 %)
    40003 - Outlet valve position (0=closed, 1=open)
    40004 - Emergency stop command (0=run, 1=stop)

  Input Registers (read-only):
    30001 - Tank level (%)
    30002 - Pump 1 current (Amps)
    30003 - Pump 2 current (Amps)
    30004 - Outlet flow rate (m3/h)
    30005 - Tank temperature (C)

This is a simulation. Not connected to real equipment.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field


@dataclass
class ProcessState:
    """Live state of the pump station. Updated every tick."""
    tank_level_pct: float = 60.0
    pump1_speed_pct: int = 40
    pump2_speed_pct: int = 40
    valve_open: int = 1
    estop: int = 0
    pump1_current_a: float = 5.0
    pump2_current_a: float = 5.0
    outlet_flow_m3h: float = 0.0
    tank_temp_c: float = 65.0
    history: list = field(default_factory=list)


def tick(state: ProcessState, dt_seconds: float = 1.0) -> None:
    """Advance the physical simulation by one time step."""
    if state.estop:
        state.pump1_speed_pct = 0
        state.pump2_speed_pct = 0
        state.valve_open = 0

    # Inflow: assume ~2 %/s at full pump speed (both pumps combined)
    inflow_pct_per_s = (state.pump1_speed_pct + state.pump2_speed_pct) / 200.0
    # Outflow: assume 1 %/s when valve is open
    outflow_pct_per_s = 1.0 if state.valve_open else 0.0

    delta = (inflow_pct_per_s - outflow_pct_per_s) * dt_seconds
    state.tank_level_pct = max(0.0, min(100.0, state.tank_level_pct + delta))

    # Current draw proportional to speed, with noise
    state.pump1_current_a = (state.pump1_speed_pct / 100.0) * 12.0 + random.uniform(-0.3, 0.3)
    state.pump2_current_a = (state.pump2_speed_pct / 100.0) * 12.0 + random.uniform(-0.3, 0.3)

    # Outlet flow rate
    state.outlet_flow_m3h = 45.0 if state.valve_open else 0.0

    # Tank temperature drifts toward 65 C with noise
    state.tank_temp_c += (65.0 - state.tank_temp_c) * 0.01 + random.uniform(-0.1, 0.1)

    # Log a snapshot for offline analysis
    state.history.append({
        "tank_level_pct": round(state.tank_level_pct, 2),
        "pump1_speed_pct": state.pump1_speed_pct,
        "pump2_speed_pct": state.pump2_speed_pct,
        "valve_open": state.valve_open,
        "pump1_current_a": round(state.pump1_current_a, 2),
        "outlet_flow_m3h": state.outlet_flow_m3h,
    })


async def run_simulation(state: ProcessState, interval_seconds: float = 1.0) -> None:
    """Run the simulation loop forever."""
    while True:
        tick(state, dt_seconds=interval_seconds)
        await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    state = ProcessState()
    print("Simulating 10 ticks to verify logic...")
    for _ in range(10):
        tick(state)
        print(f"  tank={state.tank_level_pct:.1f}%  "
              f"pump1={state.pump1_speed_pct}%  "
              f"flow={state.outlet_flow_m3h:.1f} m3/h")
    print("Simulator logic OK. Modbus server binding comes next session.")
