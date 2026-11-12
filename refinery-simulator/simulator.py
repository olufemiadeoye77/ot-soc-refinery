"""Refinery pump station Modbus/TCP simulator.

Runs a Modbus server on port 5020. Reads return live process state;
writes update the simulated process.

Register map:
  Holding Registers (read/write):
    40001 - Pump 1 speed setpoint (0-100 %)
    40002 - Pump 2 speed setpoint (0-100 %)
    40003 - Outlet valve position (0=closed, 1=open)
    40004 - Emergency stop (0=run, 1=stop)

  Input Registers (read-only):
    30001 - Tank level (%)
    30002 - Pump 1 current (A)
    30003 - Pump 2 current (A)
    30004 - Outlet flow (m3/h)
    30005 - Tank temperature (C)
"""
from __future__ import annotations

import asyncio
import os
import random
import signal
from dataclasses import dataclass, field

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import ModbusTcpServer


@dataclass
class ProcessState:
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
    if state.estop:
        state.pump1_speed_pct = 0
        state.pump2_speed_pct = 0
        state.valve_open = 0

    inflow = (state.pump1_speed_pct + state.pump2_speed_pct) / 200.0
    outflow = 1.0 if state.valve_open else 0.0
    state.tank_level_pct = max(
        0.0, min(100.0, state.tank_level_pct + (inflow - outflow) * dt_seconds)
    )

    state.pump1_current_a = (state.pump1_speed_pct / 100.0) * 12.0 + random.uniform(-0.3, 0.3)
    state.pump2_current_a = (state.pump2_speed_pct / 100.0) * 12.0 + random.uniform(-0.3, 0.3)
    state.outlet_flow_m3h = 45.0 if state.valve_open else 0.0
    state.tank_temp_c += (65.0 - state.tank_temp_c) * 0.01 + random.uniform(-0.1, 0.1)


def build_context(state: ProcessState) -> ModbusServerContext:
    """Wire the process state into a Modbus data context."""
    holding = ModbusSequentialDataBlock(0, [0] * 20)
    holding.setValues(1, [state.pump1_speed_pct])
    holding.setValues(2, [state.pump2_speed_pct])
    holding.setValues(3, [state.valve_open])
    holding.setValues(4, [state.estop])

    inputs = ModbusSequentialDataBlock(0, [0] * 20)
    inputs.setValues(1, [int(state.tank_level_pct)])
    inputs.setValues(2, [int(state.pump1_current_a * 10)])
    inputs.setValues(3, [int(state.pump2_current_a * 10)])
    inputs.setValues(4, [int(state.outlet_flow_m3h)])
    inputs.setValues(5, [int(state.tank_temp_c)])

    slave = ModbusSlaveContext(hr=holding, ir=inputs, zero_mode=True)
    return ModbusServerContext(slaves=slave, single=True)


def sync_context(context: ModbusServerContext, state: ProcessState) -> None:
    """Copy process state into the Modbus register block each tick."""
    slave = context[0]
    # Process the writes the PLC or attacker performed last tick
    state.pump1_speed_pct = slave.getValues(3, 1)[0]
    state.pump2_speed_pct = slave.getValues(3, 2)[0]
    state.valve_open = slave.getValues(3, 3)[0]
    state.estop = slave.getValues(3, 4)[0]

    # Advance the physical model
    tick(state)

    # Reflect process outputs back to input registers
    slave.setValues(4, 1, [int(state.tank_level_pct)])
    slave.setValues(4, 2, [int(state.pump1_current_a * 10)])
    slave.setValues(4, 3, [int(state.pump2_current_a * 10)])
    slave.setValues(4, 4, [int(state.outlet_flow_m3h)])
    slave.setValues(4, 5, [int(state.tank_temp_c)])


async def sim_loop(context: ModbusServerContext, state: ProcessState, interval: float) -> None:
    while True:
        sync_context(context, state)
        await asyncio.sleep(interval)


async def main() -> None:
    port = int(os.environ.get("MODBUS_PORT", "5020"))
    interval = float(os.environ.get("TICK_INTERVAL", "1.0"))
    state = ProcessState()
    context = build_context(state)

    print(f"[simulator] binding Modbus/TCP on 0.0.0.0:{port}", flush=True)
    print(f"[simulator] tick interval {interval}s", flush=True)

    server = ModbusTcpServer(context=context, address=("0.0.0.0", port))
    loop_task = asyncio.create_task(sim_loop(context, state, interval))

    try:
        await server.serve_forever()
    finally:
        loop_task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
