"""Test client for the refinery Modbus simulator.

Reads the current register state, then performs an unauthorized write
to the Pump 1 speed register. Prints results so you can verify the
server is working and the write is being applied.
"""
import sys
import time

from pymodbus.client import ModbusTcpClient


def read_state(client):
    ir = client.read_input_registers(1, 5, slave=0)
    hr = client.read_holding_registers(1, 4, slave=0)
    if ir.isError() or hr.isError():
        print("read error:", ir, hr)
        return
    print(f"  tank level:    {ir.registers[0]} %")
    print(f"  pump1 current: {ir.registers[1] / 10:.1f} A")
    print(f"  pump2 current: {ir.registers[2] / 10:.1f} A")
    print(f"  outlet flow:   {ir.registers[3]} m3/h")
    print(f"  tank temp:     {ir.registers[4]} C")
    print(f"  pump1 setpoint (HR 40001): {hr.registers[0]} %")
    print(f"  pump2 setpoint (HR 40002): {hr.registers[1]} %")
    print(f"  valve position (HR 40003): {hr.registers[2]}")
    print(f"  estop (HR 40004):           {hr.registers[3]}")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5020
    client = ModbusTcpClient(host=host, port=port)
    if not client.connect():
        print(f"cannot connect to {host}:{port}")
        return 1

    print("=== BEFORE write ===")
    read_state(client)

    print()
    print("=== Unauthorized write: Pump 1 setpoint -> 100% ===")
    r = client.write_register(1, 100, slave=0)
    print("write result:", "ok" if not r.isError() else r)
    time.sleep(1.5)

    print()
    print("=== AFTER write (pump1 current should rise) ===")
    read_state(client)

    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
